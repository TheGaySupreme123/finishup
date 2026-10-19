# FinishUP v0.1 — shared interface registry

Canonical names used across the codebase, tests, schemas, and public documentation. Code and tests
MUST use these names verbatim; a name shared across modules is registered here first. Signatures are
Python-flavored natural language and describe intent — the implementation under `src/finishup/` is the
executable truth.

## Product vocabulary

Human-facing text says **local checks** and **AI-powered review**; the wire says
`deterministic` and `semantic`. The identifiers below are frozen wire contracts and never
change; the product words are their human names.

| Product word | Wire identifiers |
|---|---|
| local check / local finding / local-check case | `FindingOrigin.deterministic`, `CheckType` `deterministic`, `CheckMode` `deterministic_only`, `SemanticReason` `deterministic_mode`, gap `no_unresolved_deterministic_findings`, `DeterministicCase`, `DETERMINISTIC_RESULT`, `kernel/deterministic_checks.py` |
| AI-powered review / AI-powered finding / AI-powered review case | `FindingOrigin.semantic_model_derived`, `CheckMode` `semantic_if_configured` / `semantic_required`, `semantic_status` / `semantic_reason`, `semantic_provenance`, `semantic_attempts`, `semantic_job`, `yoetz.semantic-case/2`, `ports/semantic.py`, `--semantic off` |
| local-only check (no AI-powered review) | `deterministic_only`, gap `semantic_review_not_requested` (recorded only where the route required review, #1041) |
| AI-powered review on, waiting for the first edit | `SemanticReason` `deferred_before_first_edit` (check-result / check-recorded 1.5.0), gap `semantic_review_deferred_before_first_edit`. Prose: "AI-powered review is on; it starts after your first edit." |

"Deterministic" elsewhere in this registry keeps its ordinary meaning — reproducible ordering,
replay, digests, and equality — and is not a check kind.

## Product name and legacy Yoetz identifiers (ADR-048)

The product was named Yoetz through 0.2.5. The shared spellings, current and legacy, live in
`finishup.legacy_names` (`PRODUCT_NAME`/`LEGACY_PRODUCT_NAME`, `APP_NAME`/`LEGACY_APP_NAME`,
`LAUNCHER_NAME`/`LEGACY_LAUNCHER_NAME`/`LAUNCHER_NAMES`, `ENV_PREFIX`/`LEGACY_ENV_PREFIX`,
`MCP_SERVER_NAME`/`LEGACY_MCP_SERVER_NAME`/`MCP_SERVER_NAMES`,
`GUIDANCE_SCHEME`/`LEGACY_GUIDANCE_SCHEME`, `REPOSITORY_DIRECTORY`/`LEGACY_REPOSITORY_DIRECTORY`).
New output uses only the current spelling. Kept literals in code carry the label
`# Frozen legacy identifier (ADR-048): <why>`.

**Frozen under protocol 0.1** (never renamed; ADR-048 §2 has the reasons): `"protocol": "yoetz"`,
`yoetz.event`, projection `yoetz/0.1.0`, `yoetz-object/1`, `application/vnd.yoetz.*+json`, the
`yoetz-<format>/1` vault, keyring and recovery format tags, `vault-root-state.yzr`, frame magics
`YZO1`/`YZV1`/`YZH1`/`YZS1`, SQLite `application_id` `0x594F4554`, every `yoetz/<name>/v<n>` domain
separator, `hmac-sha256/yoetz-privacy-egress-request-v1`, `yoetz-semantic-case-1.0.0`, keyring
services `yoetz.vault-root.v1` and `yoetz.auto-unlock.v1`, every byte under `migrations/`, the
columns `yoetz_session_id|yoetz_task_id|yoetz_writer_id` (Python names `finishup_*`), the wire
values `yoetz_engine|yoetz_cli|yoetz_owned|yoetz_runtime|yoetz_own_call|yoetz_process_state`, the
`yoetz_limit_*` prefix and the check-inspection `owner` value `yoetz`, the whole
`yoetz.<name>/<n>` schema and record tag namespace, actor ids `yoetz:<role>`, the 154 schema files
released at v0.2.5 (titles, consts and `$id`s under `https://schemas.yoetz.dev/0.1/`),
`yoetz.schema-manifest/1.0.0`, the `yoetz-config` family and owning model `YoetzConfig`, marker
files `.yoetz-*-install.json`, `.yoetz-marketplace-activation.lock`, marker keys `yoetz_version`
and `yoetz_launcher`, crash-residue prefixes `.yoetz.*`/`.yoetz-*`, `yoetz-instance-pin.json`,
`yoetz-release-runtime.json`, `[withheld-by-yoetz:possible-credential]`, `_yoetz_spool_id`, the
capture headers `# yoetz edit outcome:`/`# yoetz edit source:`, the nested-cell mark `yoetz`, and
the single `checks.toml` format value `yoetz.approved-check-policy/1`. Python member names around
frozen values may change (`McpRegistrationState.FINISHUP_OWNED = "yoetz_owned"`,
`ActorType.FINISHUP_ENGINE = "yoetz_engine"`, `LaterMaterialClass.FINISHUP_OWN_CALL =
"yoetz_own_call"`).

**Recognized under both spellings** (readers accept the legacy form; writers emit the current one):

| Surface | Current | Legacy | Names and tokens |
|---|---|---|---|
| Platform folders | `finishup` | `yoetz` | `config.paths.installation_naming()` → `InstallationNaming` `finishup\|legacy_yoetz` (ambient roots only); anchors `data/catalog.sqlite3`, `data/vault`, `config/config.toml`, `state/service.lock`; `PathSafetyError("installation_root_ambiguous")` (public code `STORAGE_UNSAFE`, recovery `local_state_repair`). A lone `config/config.toml` counts as an anchor; the remedy keeps the folders holding the vault and catalog and moves a lone settings file into the folders that hold the vault and catalog; when both names hold a vault or catalog, it keeps the installation in use and moves the other name's folders aside without deleting them, and a leftover `service.lock` from a stopped older service is moved aside the same way (no path is named). `cli/service_installation.py`: `InstallationFolders` `finishup\|legacy_yoetz\|isolated`, `installation_folders()`, `LEGACY_FOLDERS_NOTE`, `installation_naming_line()`, `report_installation_naming(stderr_writer)` (human `service status` prints the note on stderr; stdout and `--json` unchanged), `path_refusal_failure(...)` (exit 20 with token, remedy and continuation) and `path_refusal_agent_message(reason)`; `service.client.path_refusal_reason(error)`. A connect refused for a folder reason is named on every surface: CLI `control_failure`, `setup status --next`, plain `setup status` (stdout keeps the released setup-status 2.0.0 report with `service.reachable` false; the token, remedy and continuation go to stderr and the exit code is 20; seam `cli.setup._service_reachability_observed()`), `provider status` (exit 20 instead of `internal_error`; with `--json`, the `path_refusal_failure` payload on stdout), MCP public code `STORAGE_UNSAFE` (not retryable; `safe_details.reason_code` stays `endpoint_unsafe`, `diagnostic_reason` is the token) and the TUI client. Path-safety tokens `path_contains_symlink`, `path_in_repository`, `path_in_sync_folder`, `path_not_owned`, `path_shared_temp`, `permissions_too_broad` continue as `local_state_repair`. The TUI doctor entry `installation_folders` (BLOCKED on ambiguity, skipping the package-update check and status snapshot). |
| Environment | `FINISHUP_*` | `YOETZ_*` | `config.env` (`ENV_PREFIXES`, `read_env`, `canonical_env_name`, `env_names`, `EnvNameConflictError`); `ConfigError("config_env_conflict")` with `safe_name` = the `FINISHUP_` name (recovery `config_correction_required`); `paths.ISOLATED_ROOT_ENV_NAMES`, `LEGACY_ISOLATED_ROOT_ENV`, `isolated_root_variable()`; the two spellings set to different roots raise `PathSafetyError("isolation_root_env_conflict")` (public code `STORAGE_UNSAFE`, recovery `config_correction_required`; no instance disposal), while `isolation_root_conflict` stays a variable that disagrees with the runtime pin (`instance_identity_repair`); `isolation_root_invalid` → `config_correction_required`, raised from two sources whose remedy names both actions: a set variable (either spelling) that is empty, relative or not an existing directory (correct it, or unset it), or, with neither variable set, a runtime pin naming a root that is gone (recreate the instance, or run `finishup instance dispose --root <root>` to remove the stale pin; a pinned runtime never falls back to the everyday installation); `load.environment_config_path()`. `FINISHUP_MCP_DEADLINE_MS` and `FINISHUP_MCP_DEADLINE_MS_{CHECK,PUBLISH_WORK,RECEIPT,RESPOND,START,STATUS}` are allowlisted names. |
| Check policy | `.finishup/checks.toml` | `.yoetz/checks.toml` | `CHECK_POLICY_PATH`, `LEGACY_CHECK_POLICY_PATH`, `CHECK_POLICY_PATHS`, `ObservationCheckPolicyAmbiguous` (a subclass of the `invalid_approved_check_policy` failure), `ObservationCheckPolicy.source_path`; CLI reason `observation_checks_<op>_failed:policy_ambiguous`; `observe checks status` field `policy_file`. |
| Host registrations | `finishup` key and artifacts | `yoetz` key and artifacts | `legacy_registration` (MCP key) and `legacy_installation` (plugin, marketplace or tree), each `none\|legacy_only\|duplicate\|foreign` (port type `LegacyInstallation`, `LEGACY_INSTALLATIONS`); preview warnings `legacy_registration_owned`, `legacy_registration_foreign`, `legacy_registration_kept`, `legacy_registration_route_kept`, `legacy_installation_owned`, `legacy_installation_foreign`, `legacy_skill_tree_owned`, `legacy_skill_tree_retained`; notes `legacy_plugin_tree_present`, `legacy_plugin_tree_retained`, `legacy_marketplace_retained` (Claude: the shared `yoetz-local` tree and Claude's user-level registration are kept); Claude preview warnings `legacy_project_registration_removed` (this project's `.claude/settings.json` `extraKnownMarketplaces.yoetz-local`/`enabledPlugins["yoetz@yoetz-local"]` entries go) and `legacy_marketplace_replaced` (in-place update of the old folder only), with the Claude `legacy_marketplace` preview binding's `declaration` (settings key → canonical digest of the legacy entry); `McpRegistrationPreview.route_profile_before`, `legacy_kept_for`, `legacy_kept_unchecked`, `legacy_route_profile`, `legacy_kept_unreadable`, `legacy_kept_unread` (#1073; `LEGACY_UNREAD_REASONS`); `McpRegistrationError` safe detail `legacy_state` (`yoetz_owned\|foreign_present\|absent\|unknown`); preview digest tags `yoetz.mcp-registration-preview/5` (`/6` when it keeps an owned `yoetz` entry, binding `legacy_kept_for`, `legacy_kept_unchecked`, `legacy_kept_unreadable` and `legacy_kept_unread`) and `yoetz.mcp-unregistration-preview/5`; `ActivationInspection.legacy_activation`; `ActivationPreview`/`RemovalPreview` `legacy_removed_block`, `legacy_cache_versions`, `ActivationPreview.legacy_plugin_tree_planned` (the digest binds the `.agents/plugins/yoetz` deletion; kept unless every repository marketplace row is FinishUP's exact row), `RemovalPreview.legacy_marketplace_json_planned`; `recommend accept codex-plugin-activation` refusal `activation_preview_invalid` when the preview lacks a legacy field; TUI `IntegrationPlan` fields `route_profile_before`, `legacy_registration`, `activation_legacy_removed_block`, `activation_legacy_cache_versions`, `activation_legacy_plugin_tree_planned`, `legacy_skill_tree_planned`, `policy_ambiguous`, `legacy_registration_kept_for`, `legacy_registration_kept_unchecked`, `legacy_registration_route_profile`, `legacy_registration_kept_unread`, `legacy_registration_kept_lines` and properties `replacements`, `legacy_registration_kept`, `legacy_registration_route_conflict`; removal conflict details `legacy_config_marketplace`, `legacy_config_plugin`; Claude conflict details `legacy_marketplace_shared` and (on `mcp_ownership_conflict`) `legacy_registration`; connection plan changes `migrate_legacy_plugin`, `remove_legacy_plugin`, and on Codex `remove_legacy_plugin_sources` and `remove_legacy_project_skill` (either keeps a connection from reading as complete); `LEGACY_AGENT_PLUGIN_ROOT` (`.agents/plugins/yoetz`), `CURSOR_LEGACY_PLUGIN_RELATIVE_ROOT` (`plugins/local/yoetz`); `adapters/integrations/legacy_launchers.py`; `sync_committed_agent_trees.py` failure `legacy_agent_tree <path>`. |
| Host admission | `finishup` forms | exact `yoetz` forms | `HostAdmissionEntry.legacy_entries`, `HostAdmissionObservation.legacy_entries_present`, status `legacy_grant` (`absent\|in_use\|stale\|unverified`), preview warnings `legacy_entries_removed` and `legacy_entries_retained`, refusals `legacy_registration_active` and `host_admission_preview_stale` (legacy entries changed between the CLI's observation and the preview's). Codex: `adapters.integrations.host_admission.CODEX_LEGACY_PLUGIN_ADMISSION_HEADER`; `cli.host_admission.AdmissionFacts.legacy_plugin_activation` and `AdmissionFacts.legacy_name_for(entries)`; status/preview JSON `route.legacy_plugin_activation` (`true\|false\|null`, always `null` off Codex). |
| Tool and skill names | `mcp__finishup__*`, `mcp__plugin_finishup_finishup__*`, `finishup:*`, `plugin-finishup-finishup:*` | the same with `yoetz` | `domain/finishup_tools.py`: `FINISHUP_TOOL_SERVER_NAMES`, `FINISHUP_SCOPED_TOOL_PREFIXES`, `FINISHUP_PREFIXED_TOOL_PREFIXES`, `FINISHUP_SKILL_NAMES`, `finishup_scoped_tool_basename`, `finishup_tool_spelling`. Permanent. |
| Guidance URIs | `finishup://guidance/` | `yoetz://guidance/` | `protocol/guidance_uris.py`: `GUIDANCE_URI_PREFIX`, `LEGACY_GUIDANCE_URI_PREFIX`, `LEGACY_GUIDANCE_ANCHORS`, `LEGACY_ALL_GUIDANCE_URIS`, `canonical_guidance_uri`, `legacy_guidance_uri`, `is_legacy_guidance_uri`, `guidance_uri_in_scheme_of`. `resources/list` advertises `finishup://` only. |
| Agent text markers | `finishup-blocker:`, `finishup-assumption:`, `finishup-verification-limit:`, `finishup-no-material-work:`, `finishup:test-change:` | `yoetz-` / `yoetz:` spellings | `task_facts.LEGACY_BLOCKER_MARKER`, `LEGACY_DISCLOSURE_MARKERS`; `task_statement.LEGACY_NO_MATERIAL_WORK_MARKER`, `NO_MATERIAL_WORK_MARKERS`. Permanent. The `yoetz_availability` delegation block is honored like `finishup_availability`. |
| Command heads | `finishup ...` | `yoetz ...` | `consent.ConsentCommandHead`, `consent.CONSENT_COMMAND_HEADS` (`pending-agent/6` → `yoetz`, `/7` → `finishup`, `/7` also admits `yoetz`); `consent prepare\|status\|catalog` emit `/7` with the head of the invoking launcher (`yoetz` through the deprecated alias; `cli/elevated._consent_command_head()`), via `projection_for_status(..., command_head=None)`, `catalog_payload(*, command_head="finishup")`, `status_payload(*, command_head="finishup")`; a `pending/4` file holding an operation's exact pre-rename danger text (`provider_credential_set`, `provider_credential_rotate`, `repository_privacy_grant`) under a matching digest is a valid pending; validation reasons `consent_command_head_mixed`, `consent_command_head_invalid`; `observation_capacity_policy.canonical_safe_command`; unreleased `command[0]` enums `[finishup, yoetz]` in consent 7.0.0, `check-result` 1.3.0/1.4.0 and `status-result` 1.4.0. |
| Package name | `finishup` | `yoetz` | `receipts.RECEIPT_PACKAGE_NAMES` / `ReceiptPackageName`; unreleased `receipt-document`/`receipt-result` 1.3.0 `package_name` enum `[finishup, yoetz]`. |
| Launchers | `finishup`, `python -m finishup` | `yoetz`, `python -m yoetz` | `launcher.invoked_through_legacy_alias()`, `launcher.LEGACY_MODULE_NAME`, `codex_launcher.installed_launcher(name)`, `package_update.installed_package_name()`; `entry.LEGACY_ALIAS_NOTICE` (stderr, interactive only); `exits.UPGRADING_FROM_YOETZ_GUIDE`; `application/upgrade.build_upgrade_plan(launcher=..., legacy_extras=...)` step "Move from the yoetz name" (install command `PACKAGE_INSTALL_COMMAND`, shell-quoted, with the extras `legacy_tool_extras(receipt)` proves from a plain `yoetz` uv receipt; `adapters.package_upgrade.PACKAGE_EXTRAS`, `plain_uv_tool_receipt(receipt, name)` and `read_uv_receipt(prefix)` (a bounded regular file, never followed through a symlink) are the one check the in-place `upgrade --accept` also uses, refusing a non-plain receipt as `refused_custom_uv_installation`) and `ValueError("upgrade_launcher_invalid")`/`ValueError("upgrade_extras_invalid")`; `package_update.upgrade_command_for(package=...)` (`yoetz upgrade` for a transitional install, used by status, setup, TUI tips and `recommend accept package-update`); `tui.app.relaunch_command(package)` (the command the TUI's upgrade handoff says to re-run); update checks `PYPI_LEGACY_JSON_URL` and `ValueError("package_invalid")`; one update cache file per identity (`package-update-cache.json` for `yoetz`, `package-update-cache-finishup.json` for `finishup`) with an optional `package` member (`finishup\|yoetz`; absent means a pre-rename `yoetz` poll). One release. |
| Diagnostics | `finishup.<module>:<line>` | `yoetz.<module>:<line>` | Origin pattern in `observability/privacy.py`. |
| Review labels | `[FinishUP` | `[Yoetz` | The forged-label fence in `application/semantic_case.py`, any ASCII case. |

Renamed internal names that are not wire values: the gap-effect families `finishup_review_budget`,
`finishup_advice_pipeline`, `finishup_detail_bound` and `finishup_review_call`, the later-material
rule `finishup_tool_call`, `kernel.review_frame.finishup_process_state_only`, the credential
authority `finishup_vault_api_credential`, the stderr prefix `finishup_observation_detail:`, the
bundled advertised-schema `$defs` key prefix `__def_`, and thread-name prefixes
`finishup-obs-sweep`, `finishup-obs-local` and `finishup-hook-spool`.

## 1. Identifiers (`protocol/ids.py`)

All FinishUP-generated public IDs: `<prefix>_<lowercase canonical RFC 4122 UUIDv4>` from the OS
CSPRNG. Opaque, case-sensitive, never parsed for order or meaning.

| Kind (enum `IdKind`) | Prefix | Generated by |
|---|---|---|
| `request` | `req_` | client (CLI/MCP wrapper/conformance client) |
| `installation` | `ins_` | server, once per installation |
| `task` | `tsk_` | server (`start`) |
| `session` | `ses_` | server (`start`) |
| `writer` | `wri_` | server (`start`) |
| `event` | `evt_` | client (stable across retry) |
| `obligation` | `obl_` | client (payload-level, stable) |
| `claim` | `clm_` | client (payload-level, stable) |
| `action` | `act_` | client (payload-level, stable) |
| `result` | `res_` | client (payload-level, stable) |
| `evidence` | `evd_` | client (payload-level, stable) |
| `finding` | `fnd_` | server (engine) |
| `object` | `obj_` | server (object store) |
| `receipt` | `rcp_` | server |
| `correlation` | `err_` | server (error correlation) |
| `semantic_job` | `job_` | server |
| `semantic_attempt` | `att_` | server |
| `maintenance_pin` | `pin_` | server |
| `service_instance` | `svc_` | trusted local service at process start |
| `control_rpc` | `rpc_` | CLI/MCP/UI control client, stable across retry |
| `privacy_policy` | `pvy_` | trusted local service policy store |
| `privacy_setup_session` | `psw_` | trusted local service setup coordinator |
| `privacy_proposal` | `ppr_` | trusted local service privacy coordinator |
| `outbound_case` | `cas_` | trusted local service privacy coordinator |
| `egress_authorization` | `aut_` | trusted local service privacy audit authority |
| `egress_dispatch` | `dsp_` | trusted local service immediately before physical dispatch |
| `egress_receipt` | `egr_` | trusted local service privacy audit |
| `project` | `prj_` | trusted local service project coordinator |
| `actor` | `agt_` (convention) | caller-asserted; format-validated only |

`IdKind.project` uses prefix `prj_` and is server-generated under the same
`<prefix>_<lowercase UUIDv4>` rule. Catalog minting and `new_id(IdKind.PROJECT)` use the shared
identifier registry; membership commitments never substitute for a project identifier.

For `publish_work`, public event IDs are caller-generated and stable across retry. The lifecycle,
response, check, finding, and receipt events created by the engine receive IDs from the injected
`IdPort`. A resumable operation persists those allocated IDs before the first retry boundary, so a
retry reuses them rather than allocating replacements. No ID is derived from a digest, sequence,
timestamp, provider value, or database row ID.

Key functions: `new_id(kind: IdKind) -> str`; `validate_id(kind, value) -> str` (raises
`ProtocolValueError` for a protocol-invalid value); `safe_request_id_from(arguments: object) ->
str | None` (accepts only `Mapping` values, non-raising and bounded, used by MCP error paths).
Every kind parameter requires `type(kind) is IdKind`; a raw wire token or other enum is a
programmer defect and raises ordinary `TypeError("id_kind_wrong_type")`, including through
`is_valid_id`. `new_id(IdKind.ACTOR)` is the sole per-kind generation exception and raises
`ProtocolValueError("actor_id_not_generated")`. Safe extraction contains a hostile mapping's
raising `.get`, recognizes mappings by actual runtime class rather than spoofable `__class__`,
accepts only an exact built-in `str`, checks length before scanning, and returns only a validated
request ID or `None`. Direct validators accept real `str` subclasses through built-in `str`
descriptors while rejecting non-string impersonators. There is no `parse_id`, reverse-prefix
lookup, or kind-from-ID public API.

## 2. Public error codes (`protocol/errors.py`)

`PublicErrorCode` is declared exactly as `class PublicErrorCode(str, Enum)`, with explicit string
values equal to the member spellings and this frozen order:
`INVALID_REQUEST`, `PROTOCOL_VERSION_UNSUPPORTED`, `SESSION_NOT_FOUND`, `SESSION_CONFLICT`,
`IDEMPOTENCY_CONFLICT`, `REQUEST_IDENTITY_CONFLICT`, `OPERATION_PENDING`, `FRONTIER_CONFLICT`,
`EVENT_INVALID`, `LIMIT_EXCEEDED`, `BUNDLE_BUSY`, `STORAGE_UNSAFE`, `STORAGE_CORRUPT`,
`MIGRATION_REQUIRED`, `SERVICE_UNAVAILABLE`, `VAULT_LOCKED`, `PRIVACY_AUTHORITY_REQUIRED`,
`PROVIDER_UNAVAILABLE`, `PROVIDER_REFUSED`, `PROVIDER_TIMEOUT`, `SEMANTIC_RESULT_INVALID`,
`CANCELLED`, `INTERNAL_ERROR`.

`type SafeDetailValue = str | int`; emitted values are exact built-in `str`/`int`, so `bool` and
hostile scalar subclasses are excluded on every runtime path. Error codes, mappings, and trusted
Enum details are recognized from their actual runtime classes rather than spoofable `__class__`.
Exception type:
`PublicOperationError(code, message, retryable, correlation_id=None, safe_details=None)`, a frozen,
slotted exception/dataclass. After validation its `Exception.args` is exactly `(message,)`,
`str(error) == message`, and its deterministic dataclass representation contains only its five
already-safe normalized stored fields. First correlation binding returns a new value, same-ID
binding returns `self`, and different-ID binding is invalid. `as_public_dict()` returns a new
ordinary dictionary with exactly `code`, `message`, `retryable`, and bound `correlation_id`; it
adds `safe_details` only when nonempty, as a new ordinary dictionary in ASCII key order. The frozen
public-error JSON Schema remains a structural superset of this exact mapping-only runtime emitter.
Allowlisted `safe_details` keys include structural recovery fields such as `reason_code`,
`sequence`, `head_digest` (for `FRONTIER_CONFLICT` current-head recovery), validated
`task_id`/`session_id`/`writer_id` selectors, and the MCP bridge's host-binding availability
facts (`availability` = `terminal_unavailable`, boolean `availability_inherited`, validated
`availability_request_id`, and the closed `host_profile`/`route_profile` tokens; see the
availability latch under the local-control section). The initialization-required continuation
(issue #512) adds `continuation` (only `vault_initialization_required`), the exact-literal
command tokens `prepare_command` (`finishup consent prepare vault_initialize`), `review_command`
(`finishup consent review`), and `authorize_command` (`finishup consent authorize`), integer
`pending_ttl_seconds`, and validated `replay_request_id`; every command value is a closed
repository literal, so no caller- or service-derived string can steer an agent through these
keys. `SESSION_NOT_FOUND` with
`reason_code: session_superseded` carries the current binding for a retired session. A
`SESSION_CONFLICT` raised by the repository fence carries `reason_code:
repository_identity_required` (the control handshake carried no workspace locator) or
`repository_identity_mismatch` (the locator resolved to a different repository than the route, or
the route holds no repository binding); neither discloses a commitment, and a hook uses the reason
to keep a live mapping out of the `mapping_stale` class (issue #578).
The repository-fence message names missing context or the current closed identity kind
(`git_common_root` or `directory`) and directs the operator to the original workspace. It exposes
no path or commitment. Read-only operation status retains the same fence: when that workspace is
unavailable, the task workflow cannot inspect the operation (issue #444).
`workspace_task_exists` identifies an explicit `mode=create` colliding with an identical
workspace/external pair. It never refuses a new pair on the automatic admission path. The conflict
deliberately carries no task selector or count: possession of a workspace reference alone is not
authority to discover or attach another task. Automatic host hooks preflight a validated selector
from the private local lifecycle store instead of waiting for this conflict; any attach still
requires that selector, and the public error remains unchanged and reveals no binding.
Workspace membership alone never authorizes discovery,
attachment, or task selection. A live, consented project status may disclose bounded sibling
identity and state; attachment still requires a held session selector or the exact identity pair.
Conflicting START selectors return `SESSION_CONFLICT` with `reason_code: selector_conflict`
before consuming a handle or creating a child. An optional session accompanying an attach handle
must select that handle's child, and a self-registration request cannot simultaneously select an
existing session for attachment.
For MCP
`INVALID_REQUEST` validation failures, `safe_details` may also carry parallel `fields` and
`reasons` arrays: each entry is an allowlisted JSON pointer and a closed reason token for that
location (same index order; at most eight locations). `reason_code` may co-occur with
`fields`/`reasons` in the same `safe_details` — a `publish_work` validation failure whose
prior-operation lookup was unavailable carries both — and the whole mapping is emitted in ASCII
key order (`fields`, `reason_code`, `reasons`). Pointers use only trusted location segments;
unknown or hostile property names are never echoed. Closed reason tokens are:

- `missing` — a required property is absent;
- `extra_forbidden` — an additional property is not admitted;
- `invalid_type` / `invalid_value` — type or admitted-value failure at the named path;
- `invalid_type_or_value` — residual validation failure when no more specific closed token applies;
- `paired_field_required` — a schema `dependentRequired` pair is incomplete (for example `start`
  with `workspace_ref` present and `external_ref` absent, or the inverse). Both the present field
  and the required peer are named; the authoring hint states the schema peer rule (e.g.
  `workspace_ref requires external_ref`) without echoing submitted values;
- `conditional_field_required` — a root-level schema `if`/`then` (or equivalent closed object rule)
  activated required alternatives, a selected const-discriminated `oneOf` branch has a missing
  required peer or `anyOf`-of-`required` alternative (for example `start` with `mode` `attach`
  without `session_id`, `evidence_recorded` with `strength` `mutable_reference` without `reference`,
  or `strength` `metadata_only` with neither `description` nor `reference`), or a selected payload's
  `allOf` `if`/`then` required pair is incomplete (for example `content_digest` without
  `digest_binding`, or `action_kind` `command` without `command`). Named fields are the safe
  required alternatives; the authoring hint states the activating condition when it is a bounded
  schema const (e.g. `mode attach requires …`, `strength mutable_reference requires reference`,
  `strength metadata_only requires description or reference`, or `action_kind command requires
  command`) and otherwise the schema peer rule (e.g. `content_digest requires digest_binding`). A
  payload field that is required unconditionally is never this token: with no activating condition
  to state, it falls through to the residual path token instead.

These object-rule tokens are projected only from checked-in schema metadata and validator kind —
never from caller-controlled keys or free-form exception text. Unrecognized object rules degrade
to a bounded generic `INVALID_REQUEST` without inventing field pointers. A root `if`/`then`
`not required` rule (for example `status` `filter` beside a `view` that admits none) is reported
as `extra_forbidden` at the forbidden field, which is read from the schema rule and named only when
the request carries it.

Authoring hints are hint text only; they never add `safe_details` keys. For a value rejected inside
a draft payload, the hint follows the draft's own catalogued family and version (several families
share a field name with different admitted shapes), names the admitted shape of an array member
(`each limitation_refs entry admits values matching ^res_…`), states a payload array item's own
`allOf` peer rule (`each obligation_changes entry with change superseded or waived requires
reason`), names the absent keys of a payload `required` list before reciting it, and lists enums of
up to 16 members. Checked-in sentences in the MCP error module cover contract facts a pattern only
implies (which id kind a reference list names, `status` `limit`, `at_frontier`, and `filter`). The
`obligation_published` `resolution_evidence_refs` sentence also answers a rejection located at the
list itself, so a resolution that omits the list or sends it empty is told what it holds: one or
more evidence (`evd_`) or result (`res_`) ids, with every other field repeated (tb4n4, #1049).
A payload value a sibling's `const` narrows in a top-level `allOf` rule of its family (tb4n5,
#1049: `evidence_recorded` `digest_binding.subject` by `evidence_kind`) is hinted from that rule,
not from the property's union: the schema validator names the frozen `(field, const)` of the branch
the draft selected (`SchemaInstanceInvalid.condition_field` / `condition_value`, read from the
schema and admitted only when the draft's value byte-equals it), and the hint leads with that
branch's subset (`subject for evidence_kind test_result admits approved_check_receipt,
static_analysis_report, test_report, test_stdout`), then every other branch's, then each value a
peer const constrains (`approved_check_receipt needs provenance approved_check`). Without a
selected branch it names every branch. Only `field` and `reason` reach the wire.

Two request shapes are read instead of refused (tb4n4, #1049). Both are normalized by the protocol
request model before the schema check, so every surface that validates a request (MCP bridge, CLI,
service) reads them alike, and the validated request, its request digest and anything recorded are
byte-identical to the canonical spelling. A `status` `limit` sent as a JSON integer from 1 to 100 is
read as its canonical decimal string (`bool`, `0`, `101`, a float or any other value keeps the
refusal). A `decision_id` key in a `decision_recorded` draft payload is accepted and ignored: a
decision has no id of its own (it is addressed by its `event_id`), so the key is dropped before the
drafts are prepared, a retry of the same `request_id` with or without it is a replay of one request,
and the recorded event never holds it. Every other unadmitted key, in every family, keeps its
`extra_forbidden` refusal. The advertised schemas keep the one canonical spelling (ADR-002).

Server-filled publish boilerplate (issue #1084, ADR-050). A `publish_work` request
(`publish-work-request` 1.2.0 and `event-draft` 1.2.0, changed in place while unreleased) may omit
`expected_frontier` and each draft's `event_id`, `occurred_at`, `causal_parents`, `artifact_refs`
and `evidence_refs`; only `schema` and `payload` remain required in a draft. `request_id` stays
required at the service. The pure half lives in `finishup.protocol.publish_boilerplate`:

- Reference sets are canonicalized by the request model before the schema check: the envelope
  sets of every draft, and the payload fields `PAYLOAD_SET_FIELDS` names for an exact
  `(family, version)`, are sorted as ASCII bytes and de-duplicated. No other array is touched,
  whatever its members look like (a `decision_recorded` `alternatives` tuple of id-shaped text
  keeps its order and repeats); lineage and coordination payload sets keep
  `unsorted_set_field`/`duplicate_set_member`.
- An omitted draft `event_id` is `mint_draft_event_id(DraftMintScope(task_id, writer_id,
  request_id, dry_run), index)`: the whole operation key, the position and the preview/commit role.
  Two writers reusing one explicit `request_id` never mint the same id, and a preview never mints
  the ids its commit records. The session is not in the seed: a task-scoped replay of the same
  operation recomputes the same ids.
- An omitted `occurred_at` is the service clock, read once per operation. It enters the request
  identity as `null`, never as the time, so a same-id retry replays instead of conflicting.
- An omitted `expected_frontier` is the frontier the service reads when it admits the batch
  (`load_frontier`, before the batch is prepared or staged), passed through to
  `AppendCommand.expected_frontier` and enforced with ADR-022's observation-only tolerance: a
  cooperative append that lands while the batch is in flight is `FRONTIER_CONFLICT`
  (`frontier_changed`). It enters the identity as `"admission"`. An explicit `null` keeps its
  earlier meaning (`expected_frontier_required` on a state-sensitive batch; no guard otherwise);
  a supplied frontier keeps its guard. There is no omission-selected unconditional mode.
- Omitted envelope mirrors are copied from the payload (`result_recorded`, `response_recorded` and
  `coordination_disposition_recorded` `evidence_refs`; `evidence_recorded` `captured_object_id`);
  `causal_parents` defaults to empty. A sent value is never replaced, so a sent mirror that
  disagrees is still `ref_mirror_mismatch`, and a request that sends every value keeps its earlier
  identity, digest and result bytes.

Host-owned request identity (ADR-050 decision 2, revised by round 2 of the PR #1088 review).
The MCP `publish_work` tool, and `finishup publish-work`, admit a body without `request_id` (the
advertised and catalog input schemas drop it from `required`).

- **Minting.** The host mints a fresh `req_` UUIDv4 for every such call. The body is first
  validated under a provisional id, so an invalid body is never sent. A dry run gets its own
  fresh id. Nothing is persisted and nothing is resumed by content.
- **Reuse.** The bridge's own transport retries (reconnect, and the timeout probe with its
  replay) reuse the id.
- **Disclosure.** Every result and error carries it. An id-less error's text adds the line
  `FinishUP minted request_id … for this call`. `finishup publish-work` prints
  `request_id …: minted by FinishUP` on stderr before sending. When a write's result cannot be
  written to stdout, it reports `result_output_failed` with that id instead of a usage error.
- **Retry contract.** Retrying an unknown outcome means sending that id.
- **Repeat guard.** `finishup.mcp.publish_identity.PublishRepeatGuard` keeps, in the bridge
  process only, each writer's previous id-less publish that could have committed: a commitment
  over the canonical body, the id, and a monotonic time. An id-less body identical to it is
  refused before sending as `INVALID_REQUEST` with `reason_code: publish_repeat_unconfirmed`,
  continuation `publish_identity_choice`, and `safe_details.replay_request_id` naming the earlier
  id. The envelope `request_id` is absent, so no hook reads the refusal as the earlier call's
  outcome. The refusal (`retryable: false`) says a call the caller saw succeed is recorded, so a
  deliberate repeat changes the body or sends a fresh `request_id` (`req_` plus a new lowercase
  UUIDv4), and a call whose result it did not see is retried with `replay_request_id`.
- **Forgetting.** The record is replaced by the writer's next id-less publish. It is dropped by:
  - the writer's explicit-id publish that could have committed;
  - a certain pre-append rejection of that call (`INVALID_REQUEST`, `EVENT_INVALID`,
    `FRONTIER_CONFLICT`, `LIMIT_EXCEEDED`, `PROTOCOL_VERSION_UNSUPPORTED`, `SESSION_CONFLICT`,
    `SESSION_NOT_FOUND`);
  - one hour of monotonic time;
  - the 4,096-writer bound.

  Dry runs and other writers' calls never drop it.
- **No guard:** across a bridge restart, after the writer's next publish, after the hour, and for
  the CLI. An identical id-less body is then a new publication.
- **Startup gate.** The startup-gate hook never saw a minted id, so in required startup mode an
  id-less publish is admitted with no pre-call ticket. Its ticket opens only at a post-call event
  that carries the structured result naming the minted `request_id`. On Claude Code, whose hooks
  receive MCP error results as text only (or `PostToolUseFailure` with no `tool_response`), an
  id-less publish that errors or loses its reply holds no ticket, and a concurrent delegate's tool
  can pass while one is in flight (still live-probed against the current accepted plan). A retry by
  the minted id takes a ticket again; fail-closed tracking needs the caller's own `request_id`.

Provenance: every success, reduced success and dry-run result carries `server_filled` (`request`:
`expected_frontier` when omitted; `drafts`: groups of filled envelope `fields` with the batch
`indexes` they apply to) exactly when something was filled, and the publish operation's stored
result keeps the same field names (structural only, no caller content). A replay and `status
view=operation` return the committed operation's stored record, never one recomputed from the retry
body. `status view=history` items (`status-result` 1.4.0 history row) and the frozen check history
and review packet rows carry `occurred_at_source: "service_clock"` for an event whose publish
omitted `occurred_at`, derived from the appending operation's stored record; absence means
caller-asserted. Payload ids and evidence `observed_at` stay caller-authored: their payload schemas
are released.

For an `extra_forbidden` payload rejection whose unknown key is a known field with exactly one
legal owning event family among the ordinary `publish_work` families, `safe_details` additionally
carries a flat bounded repair fact (issue #266): `repair_kind` (always `field_ownership`),
`repair_field`, `repair_selected_family`, `repair_owning_family`, and `repair_template_uri`
(always `finishup://guidance/request-templates.md`), merged into the same ASCII key order. The
request stays rejected; the field is never moved or reinterpreted. The field name is admitted only
when it byte-equals a frozen catalogued payload property name (a caller-invented key can never
match), both family names come from an import-gated registry derived from the frozen `publish_work`
presentation schema, and ownership is asserted only when it is unique — ambiguous fields (for
example `statement`, `summary`), draft-envelope keys (`evidence_refs`, `artifact_refs`), fields
owned by another version of the selected family, and unknown keys all retain the plain
admitted-key answer. The same fact is repeated as one bounded sentence in the authoring hint and
as a `Repair:` clause on the compatible text summary channel, because MCP hosts are not required
to surface `structuredContent`.

The same text channel also carries a bounded `Reason:` clause when `safe_details` holds a frozen
protocol `reason_code`, optionally followed by a JSON-pointer `field` (issue #579), and a bounded
`Rejected:` clause naming up to two `reasons`/`fields` validation locations (with the remainder
counted) when a schema rejection carries those lists instead. Every token is re-gated against the
closed validation-reason set and the frozen pointer shape; the projector never copies caller prose.
Claude Code's generic MCP profile delivers only the text `content` for `isError` results, so
without these clauses an `EVENT_INVALID` set-order rejection arrived as a bare code and a malformed
`actor_id` arrived without its field. The native Cursor profile repeats the exact canonical JSON
wire body in text `content`, which already includes those `safe_details`; tests lock both
projections.

Every agent-facing surface additionally renders a **typed recovery directive** when
`safe_details` holds a registered `continuation` token (ADR-030, issue #739). The token is the only
part that travels: `finishup.protocol.recovery` holds the frozen directive sentence, an optional
`finishup://guidance/...` pointer with a section anchor, and an optional bounded nudge, and each
renderer reconstructs them locally. No `safe_details` key and no `public-error` schema version was
added to carry that prose, and a third-party consumer reading structured JSON resolves the token
through this section.

`finishup.protocol.errors` is a dependency root and holds the admitted token set literally as
`ADMITTED_CONTINUATION_TOKENS`, and the reason-to-token map literally as
`REASON_CODE_CONTINUATIONS`; `finishup.protocol.recovery` fails at import if its registry and those
disagree, so a token can never be admitted onto the wire without a directive behind it. The token
is attached where every public error is built: `PublicOperationError` adds the continuation its
`reason_code` maps to at construction, unless the producer already chose one, so a kernel,
application, service, bridge, or CLI producer that names a mapped reason ships the directive
without naming it. Two disjoint reason vocabularies resolve to tokens: protocol reason codes
through that map (and `continuation_for_reason`), and local lifecycle, instance, and ceremony
reasons through `continuation_for_local_reason`. An overlap between them is an import-time
failure.

`request_timeout` is the one reason whose directive depends on the operation kind, which only the
boundary that issued the request knows (`timeout_operation_kind`): a timed-out read
(`read_timeout_new_identity`) proves nothing committed and directs a new read identity; a timed-out
write (`write_timeout_same_identity`) leaves the outcome unknown and directs `status
view=operation` under the same `request_id`; and a timed-out `start`
(`start_timeout_same_identity`) leaves it unknown without the session and writer ids that view
requires, so it directs one exact replay of the same start body, as the shipped recovery table's
lost-start branch has always required (issue #669). When the caller cannot say which it was, no
continuation travels rather than the wrong one.

A body the schema validator rejected before any write is a **correction, not a retry**. The MCP
bridge's argument validator is the only producer of location-shaped `safe_details` (`fields` and
`reasons` lists), and it attaches `input_correction_new_identity` to every such rejection: the
field pointer and authoring hint say what to fix. An id-kind hint names the field, the closed
prefix it expects, the sent prefix when that prefix is one of the closed id kinds, and a
checked-in example id; the rest of the sent value is not copied into the hint, `safe_details`, or
logs. The directive says the corrected body is
submitted once under a new `request_id` rather than resent or treated as an ambiguous write. The
`publish_work` draft validator attaches the same token to every non-retryable `EVENT_INVALID`
whose reason has no directive of its own; it is classified at that producer rather than mapped
from the reason, because the same validation reasons also name corrupt stored records elsewhere,
where "correct your input" would be false. Two
facts a boundary knows beyond the locations override that token: a unique field-ownership repair
(issue #266) attaches `field_ownership_repair`, and an unreachable recovery oracle
(`operation_recovery_unavailable`) attaches `recovery_check_then_correct`, which requires the
original `request_id` to have a known outcome before any corrected submission.

A coverage ratchet requires every member of `PROTOCOL_REASON_CODES` to resolve to a directive or
carry an explicit exemption, so a newly registered reason code cannot reach an agent as a bare
token with nothing to do about it.

The local vocabulary ratchets the same way (issue #741). `finishup.cli.exits` fails at import unless
every reason it can put in front of an operator — the keys of `REMEDIATION_MESSAGES`,
`CEREMONY_REFUSAL_MESSAGES`, `LIFECYCLE_PUBLIC_CODES`, and `INSTANCE_PUBLIC_CODES`, plus the named
configuration-constraint set — resolves to a directive. The gate lives there rather than in
`finishup.protocol.recovery` because the protocol package may not import the CLI. A local reason is
answered through `continuation_for_local_reason`, or, for the one reason that belongs to both
namespaces (`service_draining`), through the protocol disposition already recorded for it. The one
generated family, `vault_result_*`, is matched by the prefix registered in
`LOCAL_REASON_CONTINUATION_PREFIXES`; every other local reason is enumerated. Thirteen tokens are
reachable only through the local vocabulary, and no reason code attaches them to a public error.

`REMEDIATION_MESSAGES` remains the per-reason remedy half and is not folded into the registry: the
registry is keyed by continuation token and its token set must equal the wire-admitted set, its
directives are bounded at 232 ASCII bytes, and several remedy sentences are byte-locked by CLI
tests. The remedy names which condition was hit and its exact local command; the directive names
the recovery rule for that shape. Both render, remedy first.

On the 4,096-byte MCP text channel (512 until tb4n3, ADR-043) the directive is budgeted after the
identity and reason clauses, and optional parts are dropped from the least load-bearing end — nudge,
then guidance pointer, then carried commands. The error identity is never dropped to fit advice. The CLI has no such ceiling
and renders `Continuation:`, `Next:`, `Commands:`, `Guidance:`, and the nudge on separate lines
beneath the existing `CODE: message` line, and appends the same lines to a bounded lifecycle,
instance, or ceremony refusal line whose local reason has a registered directive. Every
human-rendered CLI error path goes through one of `render_human_error`, `bounded_failure_line`, or
`ceremony_refusal_line` in `finishup.cli.render`, so the public-error renderer, the trusted-ceremony
mapper, the interactive menu, the instance and path refusal line, the observe verbs, and the
resource-integrity branch of `version` all render the same directive for the same reason. A
coordination control refusal appends the directive its reason code maps to beneath its remedy line.
Frozen command
literals already allowlisted on `safe_details` (`prepare_command`, `review_command`,
`authorize_command`) are rendered in that fixed order; which of them travel is decided upstream, so
the clause reports what is present.

JSON renderings carry the continuation token where they already carry `safe_details`. A JSON error
body the CLI owns (the observe verbs' typed `error` object and the control-failure payload with
`ok: false`) also carries a `recovery` object whenever the error resolves to a directive (ADR-030,
issue #741). Its fields mirror the human lines one to one: `continuation`, `directive`, and, when
present, `commands`, `guidance_uri`, and `nudge`. A claim-revision rejection carries `invariant` and
`correction` instead of, or alongside, those fields. The CLI resolves the text itself from the
checked-in registry, the same resolver its human lines use; nothing is read from the wire or from
the error message. `recovery.continuation` is the stable key. The prose fields are advisory, may be
reworded in any release without a schema change, and are never accepted back as input. A body with
no resolvable directive has no `recovery` key.

The workflow commands (`start`, `publish-work`, `check`, `respond`, `status`, `receipt`) print the
frozen `operation-result-1.0.0` failure body on stdout in JSON or non-TTY mode. That schema admits no
additional property, so stdout stays byte-identical to the wire result, and the CLI writes the same
directive lines a terminal would show (`Continuation:`, `Next:`, …) to stderr. Exit codes are
unchanged throughout.

For `claim_revision_mismatch`, `safe_details` carries an allowlisted `invariant` naming the closed
domain rule that rejected the draft, and both the MCP text projection and the CLI render an
`Invariant:` plus `Correction:` clause from it. The corrective phrases live in the shared recovery
registry beside the continuation directives (ADR-030), so the same rejection reads the same way on
both surfaces; the CLI previously rendered no correction at all. For `limitation_refs_complete` the
rejection also names the missing live result ids: `safe_details.count` is their number and the
message lists up to 32 of them in ascending order (structural ledger ids, never caller content),
so an author can disclose hook-observed failures it never published without reading every result.

The invariant vocabulary is closed and gated twice: `finishup.protocol.errors` holds
`ADMITTED_CLAIM_REVISION_INVARIANTS` literally because it is a dependency root, `finishup.domain.events`
reuses that set rather than restating it, and `finishup.protocol.recovery` fails at import unless every
admitted invariant has a correction. An unregistered token is stripped by the normalizer and the
clause is omitted.

Until ADR-030 the invariant travelled only inside the public error message, and the projector
recovered it by matching that whole sentence with a regex — so a reworded message silently cost the
agent the correction. The clause is now independent of message wording, and the projector still
never echoes the message.

Provider and AI-powered review outcomes (issue #742) resolve through
`continuation_for_semantic_outcome`. The adapter classifies the physical attempt into the closed
`SemanticFailureClass` set and discards raw provider text there. Renderers look up a frozen
directive from the recorded `(semantic_status, semantic_reason)` pair and, when present, that
`failure_class`. A rejected credential (`authentication` / `authorization`) maps to
`semantic_credential_rejected` even when the public reason remains the `transport_unavailable`
catch-all; truncated or overlong output maps to `semantic_response_truncated` from
`response_content_invalid`; schema-invalid and rejected-judgment answers map to
`semantic_response_invalid`; capacity and quota map to `semantic_capacity_exceeded`; and
`retry_budget_exhausted` and `outcome_unknown`, which name how a job ended rather than why, map to
`semantic_no_judgment`. Every directive follows the check-mode coverage guidance: it never tells an
agent to downgrade a required review, and it never offers a second job for a truncated answer.
Predispatch configuration and policy outcomes (`not_configured`, `credential_unavailable`,
`blocked_by_policy`, and the rest) carry no directive. These tokens
are admitted continuation tokens and live in the same registry. They are not new public
`SemanticReason` values and do not change frozen check-result schemas. CLI check rendering and the
MCP check text summary project the resolved directive (the MCP channel drops the sentence when the
bounded budget cannot hold it, keeping the token). Hook advisories never carry a provider-outcome
token: a hook token is resolved from the hook's own exact reason (`render_hook_recovery_suffix`),
and today only SessionStart's vault-locked advisory has one (`vault_unlock_required`). Hook contexts
shared by several reasons (the status-read retry class), the service's retryable `storage_unsafe`
fault, and a timed-out attachment keep their own instruction without a token. The TUI blocked report
and receipt human text project the full directive lines from the registry. Compact receipt sentences
stay frozen. Advice and status `semantic_state` is the recorded attempt status (`ready` / `disabled`
/ `unavailable` / `failed`), not finding presence: a successful review with zero findings is
`ready`, and `disabled` means no attempt was requested or configured. The state does not widen
coverage: only validated AI-powered finding ids add `semantic_model_derived` to advice coverage.

Every MCP result also carries a bounded ASCII text projection (the compact summary is at most 4,096
bytes; 512 until tb4n3, ADR-043; the check-totals line, manifest line, reviewer output and publish
blocker notices follow it under their own bounds) for hosts that drop `structuredContent`. The projection is composed, not
concatenated: the verdict or state, the task continuation, the frontier with its head digest and the
review status/reason are reserved first and optional clauses are granted room by priority, so it
never raises and no data-only change can turn a committed operation into an error. A clause that
fails to render is omitted and named as `summary_render_failed:<builder>.<clause>`; a builder whose
core fails falls back to the verdict or state token, the frontier and "read status view=compact".
Each such failure is a service diagnostic (operation `<builder>_summary_degraded`, phase
`<builder>.<clause>`), never an error result. Id and token lists are capped at 1,024 characters each
with an exact `+N more`. A successful projection includes the first valid returned frontier's
`sequence` and canonical `head_digest` when both are present. Generic successful operations also
include any returned, kind-valid `task_id`, `session_id`, and `writer_id`; in particular, the
`start` text alone carries the identifiers and frontier needed to author the next request. A
`check` projection includes as many returned, kind-valid `finding_id` values as fit and reports a
`+N more` remainder when any valid finding IDs do not fit, so the text fallback can author the
required `respond` request. Status `compact`/`obligations` projections likewise carry as many
kind-valid obligation IDs as fit, and receipt projections carry open obligation IDs plus
schema-gated ASCII-safe coverage gap codes, so a text-only host can recover closure work and name
an honest limitation without copying obligation or gap prose. Caller-controlled prose, malformed
identifiers, and malformed digests are never admitted to this text channel. A local
finding's structured `detail` may name only its closed policy facts and typed server IDs; it never
copies ledger-authored prose.

The host-facing MCP `outputSchema` also projects fixed `prefixItems` tuples into a bounded
`items.anyOf` declaration for validators that still apply legacy `items` semantics. This weakens
only the declaration used by the host: every returned result is first validated against the exact
immutable catalogue schema, which retains tuple order, length, and member identity.

The bridge accepts a serving host identity with `--host generic|codex|claude|cursor`. `generic`
leaves the host unproven and is the default for portable/manual carriers; it never implies Codex.
The native Codex and Claude carriers use `--host codex` and `--host claude` respectively, while the
native Cursor profile starts the same bridge with `--host cursor`. Cursor `3.17.x` does not
reliably deliver `structuredContent` to its model, so this explicit host profile repeats the exact
canonical JSON wire body as the single text `content` item while retaining `structuredContent`
unchanged. It adds no field and grants no additional read authority: payload-bearing fields appear
only when the ordinary service route already returned them. Generic and portable Agent Plugin
routes keep the bounded weaker projection above, preserving the shared portable bundle bytes. Host
identity is a serving and diagnostic fact; it does not grant host admission or agent-chat
attestation, which retain their independent client allowlists and authorization checks.

`read_guidance` is the one success result whose text `content` normally repeats a whole document:
generic, Claude and Cursor hosts receive the guidance text in both `content[0].text` and
`structuredContent.text`. On the `codex` profile only (issue #918), `content[0].text` is a bounded
ASCII pointer, `Guidance <uri>: <n> bytes; full text in structuredContent.text.`, built from the
registered URI and byte count alone. `structuredContent`, and so the `read-guidance-result` schema,
is identical for every host. This item is revertible: it stays only while Codex dogfood shows no
additional guidance re-read turns.

The current `read_guidance` input/output route is `1.1.0` and keeps the frozen `1.0.0` schema
available for older clients. A URI-only request returns a whole document up to 64 KiB; a larger
document automatically selects page zero with continuation metadata. The document and offset
bound is 1 MiB, while legacy body and individual-page limits stay unchanged. A request carrying
canonical string `page` and bounded `page_size` explicitly selects the page route. Its
success body adds stable `document_id`, source-byte `revision` and `digest`, total and page byte
counts, page offsets/counts, `complete`, and (until the final page) an exact `continuation` that
repeats the URI, next page, page size, revision, and digest. Pages never split a UTF-8 scalar.
The Codex text channel remains a bounded pointer to `structuredContent.text`; generic, Claude, and
Cursor paged text carries explicit begin/end markers. A final page's `complete: true` is a service
emission fact, not proof that the host delivered the page. A consumer must reject clipped markers,
missing or duplicate pages, changed revision/digest, byte-count or offset mismatches, and a final
assembled digest mismatch before exposing the document or claiming guidance is loaded. The
supported bounded consumer is `GuidancePageAssembler`; a rejected page has a bounded retry path,
and a revision change restarts at page zero. Callers assemble all pages when they need a source
document larger than the legacy full-response bound.

Page zero of a paged read also names the resource's sections (tb4n5): an optional `sections` array
of `{uri, byte_count}` entries, one per catalogued heading topic that starts inside the resource,
in document order (every catalogued topic for a whole document; the nested catalogued topics for a
heading topic; none for a focused topic, in which case the field is omitted). It is generated by
`mcp.resources.guidance_sections` from the closed topic catalog and the packaged bytes, so it names
exactly the anchors `read_guidance` admits; at most 128 entries; never present on a later page or an
unpaged read. tb4n5 agents read the 80 KB request templates whole 34 times and then paged or
guessed anchors; the list tells them which one section to read instead. On generic, Claude and
Cursor hosts the page-zero text appends the list after the page's end marker, starting
`FINISHUP_GUIDANCE_SECTIONS document=<uri> count=<n>`, one `#<anchor> <bytes>` line per section. It is
outside the page bytes: `GuidancePageAssembler` accepts that trailer only on page zero and only
directly after the end marker, and still checks exactly the text between the markers. The Codex
pointer adds the anchors and sizes beside `structuredContent.sections`.

The five legacy document URIs remain the stable `resources/list` entries. `read_guidance` also
accepts exact registered focused topic URIs and heading topics: a topic is the document URI plus a
lowercase hyphen heading anchor (for example, `finishup://guidance/workflow.md#start-and-resume`;
repeated headings use a numeric suffix). The service resolves that anchor to the complete Markdown
section, keeps the anchored URI in `document_id` and every continuation, and bounds the section
before paging. Runtime admission uses the closed topic catalog while the advertised schema uses a
compact URI pattern so the full heading catalog is not repeated in every host tool declaration. A
parent document remains available for fallback and full archival reads; a topic read is the normal
continuation when one procedure is named. A `read_guidance` call whose anchor on one of the five
documents is not catalogued but names exactly one catalogued topic of that document reads that topic,
and the result's `uri` is the catalogued one (tb4n4, #1049; `mcp.resources.resolve_guidance_topic_uri`).
The anchor names a topic when it is the topic's anchor once case, `_` and punctuation fold the shared
slug way (`publish_work-decision`), an explicit `<a id>` target the document writes under that
topic's heading (`publication-policy.md#attempt-accounting`), or words that all appear in that
topic's anchor and in no other anchor of the document (`request-templates.md#decision`). Two or more
candidates never resolve; `resources/read` keeps exact URIs. The guesses tb4n5 agents made are
explicit `<a id>` aliases (#1049): `request-templates.md#publish-work` and
`#ordinary-publication` read `#publication-templates` (the list of every `publish_work` template's
exact URI), `request-templates.md#plan-and-obligations` reads
`#publish-work-plan-plus-obligation`, and `publication-policy.md#plan-and-obligations` reads
`#obligations-evidence-and-claims`. Ordinary publish is the one topic
`request-templates.md#publish-shapes` (plan, obligation, action, result, evidence, claim, revised
plan, and decision). Any other anchor outside the catalog
on a registered document is
rejected as `INVALID_REQUEST` with `safe_details.field = "/uri"` and a message listing that
document's registered anchors plus the whole-document retry; an unregistered document lists the
registered document and focused-topic URIs. Only catalog constants appear; the caller's URI is
never echoed. `resources/list` omits `annotations.priority`, because Codex's rmcp client cannot
decode a fractional number in that result (see the Codex integration runbook).

Protocol reason
`expected_frontier_required` marks a state-sensitive `publish_work` batch that sent
`expected_frontier: null` (omitting it is guarded by the admission-time frontier, issue #1084). It names that field and is retryable because validation wrote
no durable operation; the caller may reuse the same `request_id` with a corrected body. Here
`retryable` describes whether safe recovery exists for the durable state reached, not whether the
request bytes must remain unchanged. Its continuation is `frontier_held_required` (tb4n5, #1048):
send the frontier the caller already holds (the `frontier` `start` returned for the first plan,
otherwise the `result_frontier` of its last accepted write), never a status read. A stale supplied
frontier remains `frontier_changed`, whose continuation `frontier_refresh_required` reads `status`.
The `expected_frontier` field description every write tool advertises, the publication policy, the
request templates and the operating card name the same source; the `start` and accepted
`publish_work` text summaries say which write sends the returned frontier next.

For an accepted state-sensitive batch, `expected_frontier` is task-scoped. Under ADR-022, a held
frontier may trail the current head only when every intervening record is observation-authored under
the exact service-derived predicate; the batch appends at the real head and reports that head as
`subject_frontier`. Any cooperative or imported intervening record still raises
`FRONTIER_CONFLICT`.

`response_projection_failed` marks a post-commit shaping failure for non-`publish_work` writes (and
for the genuinely impossible case where even the minimal publish envelope cannot be built): the
write may already be durable, so the public error is retryable and one same-`request_id` replay
loads the stored result; if that replay also fails the failure is deterministic and the caller reads
`status view=operation` for the committed outcome and never repeats the work under a new
`request_id`. The remedy renders on the MCP text channel as well as in the message. A failure to build the MCP *text* of a committed result is not an error at all
(ADR-043): the structured result is returned and the failure is a diagnostic. The bridge's own
structural failure after a commit (the result cannot be serialized, or does not match its response
schema) is `INTERNAL_ERROR` with reason `bridge_result_wire_failed` or
`bridge_result_validate_failed`, non-retryable; for a write it names `status view=operation` rather
than a replay that would rebuild the same result, and for a read or dry run it says nothing changed. For `publish_work`, a post-commit projection failure after a successful append is
not reported as an error at all. The daemon returns a reduced total-acceptance success branch
with `ok: true`, `response_completeness: "accepted_projection_unavailable"`,
`reason_code: "response_projection_failed"`, a `correlation_id` for operator diagnostics, the
subject/result frontiers, and accepted event ids, entry digests, and ingestion sequences — built
only from `AppendResult` / the closed internal result, never from privacy projection. The caller
does not need a second `status` call or a same-`request_id` replay to learn what landed.
For `publish_work`, completed-operation replay is resolved before body preparation and before
`expected_frontier`; it never re-appends the accepted events. Replay keys only on
`(task_id, writer_id, request_id)` from the request envelope. When the body matches the stored
request digest, the stored result is returned. When the same `request_id` is reused with a
different body (or a body that cannot be prepared), the public code is
`REQUEST_IDENTITY_CONFLICT` with `reason_code: request_identity_conflict`, carrying the committed
`sequence`, `head_digest`, and accepted-event `count` — never `INVALID_REQUEST` and never a second
append. If an exact validated full success body was durably stored, replay to the same ordinary
disclosure sink returns that body without running privacy projection again.
An accepted event's optional `summary` is non-null when present. Until publication supplies an
actual summary, the field is absent from both the internal projection document and the public
success body; an absent summary is never materialized as JSON `null` or reported as policy-omitted.
Optional `dry_run: true` on `PublishWorkRequest` validates the full batch and returns
`outcome: "dry_run"` with `evidential: false` and a `would_accept` preview (event ids, schema
identity, refs) plus coverage/gaps. It appends nothing, records no operation, does not consume
`request_id`, and does not move the frontier — same non-citable discipline as
`status view=candidate_findings`. A subsequent real publish may reuse the same `request_id`; an
id-less dry run through the bridge or the CLI gets a fresh unbound id, and its minted event ids are
never the commit's.
`dry_run: null` is rejected; omit the field or pass a boolean.
The coverage on an accepted internal success is derived from the authored envelope coverage and the
resulting projection, so its diagnostic `known_gaps` are reporting output and must not be copied into
the coverage of a later event envelope.
The preferred recovery read after any ambiguous write is `status view=operation` with
`filter.operation_request_id` set to the write's `request_id`: it is a state lookup for that
operation identity (`absent`/`pending`/`complete`/`quarantined`) within the authenticated task,
without requiring a reconstructed publish body. The task-scoped read intentionally survives a
same-task attach that rotates the active session and writer; it never crosses a task bundle.
Stored result detail is state-conditional: only
`complete` + `publish_work` carries outcome, subject/result frontiers, and accepted event
ids/digests; `pending`/`quarantined` report kind without those fields; `absent` reports none of
them; non-publish completions report kind without append-shaped event detail. A pending check that
is awaiting repository setup or a one-use disclosure decision reconstructs its typed continuation
from the routed task ledger using the operation's recorded writer, so a same-task session/writer
rotation does not strand the decision. A pending or complete check may also carry structural
`semantic_progress` (see "Structural semantic progress"). An `absent` page for a check that this
service is admitting, or recently refused before admission, carries a structural `admission` stage
(see "Check admission stage"); an `absent` page without it is a request this service knows nothing
about. Lookups are scoped to the authenticated task. A request from another task is reported as
absent.
Every `status view=findings` item carries `finding_frontier` (status result schema 1.4.0; omitted,
never null, only by older producers): the sequence of the ledger event that carries the finding's
current record and that event's own entry digest as `head_digest` (issue #917). It is identical for
deterministic, AI-powered review and observation-origin findings, follows the item's
`subject_frontier` (which names the tested state and precedes the record), and `respond` accepts it
as `finding_frontier` as-is; any later in-chain frontier remains accepted. The CLI and terminal
interface print it under each finding, and the MCP text summary lists bounded
`finding frontiers:` pairs.
MCP `publish_work` performs the same envelope-first operation lookup when the supplied body fails
schema validation (so a malformed retry body can still recover a committed operation) — except
under a declared `dry_run: true`, which appends nothing, so no prior-operation lookup can change
the answer to a body that already failed local validation: it returns the field-pointed
`INVALID_REQUEST` with no service round-trip at all (#239). Only the exact boolean `true`
declares a dry run; any other value is itself a validation defect and buys no shortcut. For real
submissions, recovery result selection is a closed tri-state:
- **found** (`pending` / `complete` / `quarantined`) replaces the body-validation result with the
  bounded recovery meaning for that state;
- **authoritative absent** returns the original field-pointed `INVALID_REQUEST`;
- **lookup unavailable** (connection, timeout, projection, or unexpected recovery failure,
  including a nested `read_projection_failed` on the internal status read) returns non-retryable
  `INVALID_REQUEST` whose message states the two facts known for certain — this body failed
  bridge-local validation, and the service could not be reached to check the `request_id` — with
  the field-pointed locations plus `reason_code: operation_recovery_unavailable` in
  `safe_details`. Recovery never masks a known authoring error (#65, #239): the remedy is to
  correct the named fields and resubmit; the service remains the authority on request identity
  and will replay or reject the `request_id` itself if it already names a committed operation. An
  unavailable recovery oracle must never claim that durable state did or did not change, must
  never tell the caller to mint a new `request_id`, and must never promote a nested status
  request id or nested read-only durability message as the outer publish result.
`read_projection_failed` is the read-only counterpart for direct status/receipt reads: nothing
was appended, so the remedy is repeating the request rather than a same-`request_id` replay that
has no operation record to load.
When a non-publish write surfaces `response_projection_failed` and the committed frontier is known,
the control error also carries `sequence`, `head_digest`, and `count` in `accepted_state` /
`safe_details`.

MCP resource discovery: `resources/list` serves the five `finishup://guidance/*.md` entries and
validates against the MCP `ListResourcesResult` schema (`tests/subprocess/test_mcp_resource_discovery.py`).
A schema-valid list payload does not mean every host delivered it: some Codex builds reject
`resources/list` with `Unexpected response type`. That error is not a missing FinishUP field:
`rmcp 3.0.0` (the crate Codex `0.148.0-alpha.6` pins) decodes the live list payload as
`ServerResult::ListResourcesResult` for the full registry shape and for the
`title` / `annotations` / `size` / minimal (`uri`+`name`) subsets. Stripping optional
resource fields therefore cannot change the typed variant. Step 0 names exact URIs and does
not use list as a discovery step. A list failure is not a missing server.
`resources/read` advertises the same registry `media_type` that `resources/list` serves as
`mimeType`; it does not hardcode a markdown type.
`resources/templates/list` answers method-not-found because no templates are declared and the
capability is not advertised — that pairing is conformant and is asserted, not "fixed". Guidance
must not present MCP resource-template discovery as a recovery path. The static
`finishup://guidance/request-templates.md` resource is an ordinary guidance resource: it carries
complete, schema-valid fallback request bodies for the six operations and all eighteen families
`publish_work` admits (`ORDINARY_MCP_PUBLISH_EVENT_FAMILIES`: the nine ordinary families, seven
delegation and work lifecycle families and two coordination families). The ordinary seven shapes
are also one topic, `#publish-shapes`, so one `read_guidance` returns that path. It does not weaken
catalog admission or add an MCP resource template.

MCP `tools/list` uses `ToolDescriptor.advertised_input_schema`, a compact authoring projection
with a CI-enforced 4,800-byte target per tool (compact ASCII JSON), on both routes and every host
profile. Field descriptions remain intact when the projected tool fits. Larger tools restore
descriptions greedily, prioritizing `await_observations`, response disposition and finding-frontier
rules, final-review/mode selection and write-frontier guidance. If even the description-free form
exceeds the target, runtime serving emits the closed diagnostic
`mcp_advertised_input_schema_over_budget` and returns that minimal form without refusing bridge
startup; CI still rejects the size regression. Payload hints must admit the types and enums of
every ordinary family/version in the full authoring graph.
Codex 0.162.1 rewrites inputs above its 5,000-byte threshold; staying below it preserves the
intended inline shapes and enums. The projection keeps request fields, required lists, event
envelopes, ordinary family names and common plan/action/result payload field types and enums,
while moving examples and event-payload discrimination to
`read_guidance` at `finishup://guidance/request-templates.md`. Canonical decimal strings retain their
syntax and documented int64 bound without repeating the full range regex. It is deliberately
permissive for payload variants and some conditional rules, never an admission schema.
`ToolDescriptor.input_schema` retains the full authoring graph and examples for repair hints;
`catalog_input_schema` and the request models retain strict server validation. Output schemas,
including Cursor's tuple compatibility projection, are unchanged. CLI, hooks, TUI and receipt
validation do not use the compact advertisement.

Internal-only value error: `ProtocolValueError(reason_code: str)` — bounded reason codes, never
free text from input. CLI exit classes (0/2/10/11/20/30/40/70/130) map from codes in
`cli/exits.py` only.

## 3. Protocol constants (`protocol/models.py` unless noted)

- `PROTOCOL_VERSION = "0.1"`; request/result `schema_version = "1.0.0"` per operation.
- `MAX_EVENTS_PER_BATCH = 100`; `MAX_CANONICAL_REQUEST_BYTES = 1_048_576` (1 MiB);
  `MAX_FINDINGS_DEFAULT = 3`; `MAX_FINDINGS_LIMIT = 10`; `MAX_REASON_BYTES = 4_096`;
  `MAX_OBJECT_PLAINTEXT_BYTES = 4_194_304` (4 MiB, ADR-004).
- Event/value bounds: `MAX_TEXT_BYTES = 8_192`, `MAX_LABEL_BYTES = 256`,
  `MAX_REF_LIST = 64`, `MAX_CAUSAL_PARENTS = 32`, `MAX_REQUESTED_ITEMS = 64`,
  `MAX_ALTERNATIVES = 16`, and `MAX_JSON_DEPTH = 64`. `protocol/canonical.py` owns and exports
  the one depth constant; every other validator, including `domain/values.freeze_json`, imports it.
  No second depth-cap symbol exists.
- `STATUS_PAGE_DEFAULT = 50`; `STATUS_PAGE_MAX = 100`.
- `LEDGER_READ_PAGE_SIZE = 500`; adapters paginate canonical event reads at this exact internal
  page size and release the read transaction between pages.
- `MAX_IMPORT_SOURCE_BYTES = 4_194_304` (4 MiB); `MAX_IMPORT_LINE_BYTES = 1_048_576`
  (1 MiB). v0.1 rejects cap-plus-one exact-source imports rather than claiming chunk support.
- `MAX_SEMANTIC_ITEM_BYTES = 16_384` (16 KiB);
  `MAX_SEMANTIC_CASE_BYTES = 262_144` (256 KiB), measured over canonical minimized case bytes.
- AI-powered review structure: `MAX_REVIEW_TEXT_BYTES = 4_096`,
  `MAX_REVIEW_TIMELINE_ITEMS = 64`, `MAX_REVIEW_ASSESSMENTS = 64`,
  `MAX_REVIEW_CHANGE_OBSERVATIONS = 32`, `MAX_REVIEW_EXCERPTS = 64` (a protocol maximum; the
  privacy-policy 1.0.0/1.1.0 wires cap `max_excerpts` at 16, see "Excerpt count"),
  `MAX_REVIEW_OMISSIONS = 64`, and `MAX_REVIEW_CHALLENGES = 3`.
- MCP transport cap (`adapters/mcp_stdio.py`): `MAX_JSON_FRAME_BYTES = 1_048_576` payload bytes
  excluding the single LF. This is adapter-owned and is not exported or mirrored by
  `protocol/models.py`. The same adapter bounds inbound nesting at
  `MAX_JSON_NESTING_DEPTH = MAX_JSON_DEPTH` (64 container levels including the root object) with a
  non-recursive walk; a deeper or otherwise undecodable frame yields the fixed null-id
  `invalid_json` parse error and the bridge keeps serving later frames (issue #394).
- Local-service control framing (`service/control_protocol.py`):
  `MAX_CONTROL_FRAME_BYTES = 6_291_456` payload bytes excluding the four-byte length prefix, with
  `MAX_ORDINARY_CONTROL_FRAME_BYTES = 1_048_576` for every frame except the exact closed
  `import_codex_jsonl` call. That one branch may exceed the ordinary cap only when its canonical
  base64 decodes to at most `MAX_IMPORT_SOURCE_BYTES`; no other method inherits the larger bound.
  Both peers read a frame in chunks of at most `MAX_CONTROL_RECEIVE_CHUNK_BYTES = 65_536`, the
  authenticated Unix stream's per-`receive` ceiling; the stream refuses a larger single receive.
  Asking for a whole frame at once made every frame over 64 KiB unreadable as `frame_invalid`,
  which a privacy receipt page of about 45 receipts reached (issue #921). A declared length above
  `MAX_CONTROL_FRAME_BYTES` is refused as `frame_too_large` after the four-byte prefix, before any
  body byte is read. Once a frame's first byte arrives, the whole frame must arrive within
  `CONTROL_FRAME_READ_DEADLINE_SECONDS = 60`, whether or not the session has calls in flight;
  waiting for a frame to begin stays governed by the handshake and inactive-session deadlines. A
  frame that misses it fails as the internal `frame_read_timeout`. The service closes the stream
  on either refusal without a reply and records an owner-only diagnostic
  (`service.daemon`/`control_frame_read`); a client whose response frame stalls reports the
  retryable `service_unavailable`. Neither reason is a new wire token.
- Host hook ingress (`cli/hook_io.py`): `MAX_HOOK_STDIN_BYTES = 1_048_576` (1 MiB) is the trusted
  full-parse cap for every host's hook stdin body and is shared by `cli/hooks.py`. It was 256 KiB
  until tb4n1 (B5), when FinishUP's own `closure_prepare` replies, image views, and large command
  outputs outgrew it and lost their PostToolUse rows. A body at or under that cap is parsed in
  full; captured content stays bounded by the separate content budget, so a large output becomes
  truncated content (`truncated_payload`), not a dropped event. The pure readers
  (`read_hook_payload`, used by the start-correlation, session-start and prompt entry points, and
  Cursor's `read_cursor_hook_payload` replay) raise `payload_too_large` before the NUL scan, the
  UTF-8 decode, and the JSON parse when the body is over that cap; an empty body still raises
  `invalid_event_value_type`. The observation readers for all three hosts (`read_hook_ingress`
  for Codex and Claude Code, `read_cursor_hook_ingress` for Cursor) read a complete body up to
  `MAX_HOOK_SKIM_BYTES = 8_388_608` (8 MiB). Inside that skim cap the same safety rules parse the
  document (a nested fractional number becomes `null`; nothing else is relaxed), and inline image,
  audio, and video bytes are replaced with a fixed placeholder (`strip_hook_media`: MCP and Claude
  `image` blocks, Responses `input_image`, any object declaring an `image/`, `audio/` or `video/`
  media type, and any such `data:` URL). If that brings the body under the trusted cap it is
  admitted whole, with no gap. Otherwise the handler keeps a closed identity view: session, turn,
  transcript and lineage locators, tool, call id, bounded path text used only for a path
  commitment, scalar outcome fields, and whether an `error` value was set (never its text). A
  `workspace_roots` value the view cannot keep becomes `null`, so the workspace resolver refuses it
  exactly as it does at full size. File contents, edits, prompts, and command text are not
  retained. That row records `payload_content_omitted` and `<host>_payload_content_omitted`,
  except for FinishUP's own MCP tools in any host spelling (`closure_prepare` included), whose
  content is never captured, so the identity row is complete and records no gap. A body over the
  skim cap raises `payload_too_large` before any parse, and so does one whose JSON structure
  (`{`, `[` and `,` outside strings) exceeds 262,144 tokens, which bounds the skim's parse time
  and memory (a real 1 MB `closure_prepare` reply carries about 30,000). A complete oversized body that fails the
  NUL, UTF-8, duplicate-key, or JSON checks yields no identity view (issue #667).
- Observed images (`cli/hook_io.py` `observed_image_facts`, P3-2, issue #1013): before media
  bytes are dropped, every host ingress records at most `MAX_OBSERVED_IMAGES = 8` images per
  event as the reserved structural member `observed_images` of a `PostToolUse` envelope (any host
  value under that name is discarded). Each item is exactly `content_digest` (`sha256:` of the
  decoded bytes), `byte_count`, `media_type` (sniffed from the bytes: `image/png`, `image/jpeg`,
  `image/gif`, `image/webp`, or `image/unknown`), and optionally both `width` and `height` from
  the header alone (never for `image/unknown`). Control-request 2.9.0 (unreleased, additive in
  place) and `domain/observation.validate_observed_images` admit exactly that shape. The service
  materializes one `evidence_recorded` 1.2.0 per item (`artifact`, `content_digest`,
  `digest_binding {artifact_bytes, digest_only, byte_count, observation_captured}`, stable id from
  source identity and image index, description `Observed image tool result <media_type> <w>x<h>
  (<n> bytes); pixels were not captured or sent`) and lists it in the call's
  `result_recorded.evidence_refs`. No pixel is captured, stored, or sent.
- Digests render as `sha256:<64 lowercase hex>`; commitments as `hmac-sha256:<64 lowercase hex>`.
- Writer/ledger sequences and frontier sequences cross the wire as canonical base-10 integer
  strings (`"0" | [1-9][0-9]*`, with writer/ledger sequences positive). This is not a blanket
  rule for every count or byte length: fields whose frozen schema type is integer remain JSON
  integers. In particular `AcceptedEvent.payload_ref.plaintext_size` is a JSON integer in
  `0..4_194_304`, and finding/receipt suppression counts and plan versions remain their registered
  JSON integer types.
- Timestamps: RFC 3339 UTC, exactly three fractional digits, `Z` suffix.
- Genesis predecessor digest: literal string `"genesis"`.
- Canonical FinishUP JSON media types are `application/vnd.yoetz.<schema_name>+json`, where
  `<schema_name>` is the registered lowercase dot-free schema token. Generic `application/json`
  is accepted only for explicitly listed imported/captured material, never as a substitute for a
  known FinishUP schema media type.

## 4. Canonicalization (`protocol/canonical.py`)

- `JsonValue` is exactly the recursive alias `None | bool | int | str | list[JsonValue] |
  tuple[JsonValue, ...] | Mapping[str, JsonValue]`; arbitrary `Sequence` implementations are not
  protocol arrays.
- `canonical_encode(value: JsonValue) -> bytes` — restricted-JCS bytes (ADR-002).
- `canonical_digest(value) -> str` — `"sha256:" + hex(sha256(canonical_encode(value)))`.
- `strict_json_parse(data: bytes | bytearray) -> JsonValue` — snapshots a `bytearray` once to
  immutable bytes, then performs strict UTF-8 parsing and rejects BOM/NUL, duplicate keys,
  floats/NaN/Infinity/-0, integers outside ±(2^53−1), and lone surrogates.
- `ensure_canonical_set(values: list[str] | tuple[str, ...]) -> None` — the outer value must satisfy
  `isinstance(values, (list, tuple))`; every other type raises `unsupported_json_type`;
  non-string or non-ASCII members raise
  `set_member_not_ascii`; equal/descending neighbors raise `duplicate_set_member`/
  `unsorted_set_field` without normalization.
- `entry_digest(preimage)` owns only the exact 18-key top-level accepted-record-preimage gate,
  `protocol == "yoetz.event"`, and canonical-value validation. Deep accepted-event schema/domain
  validation remains with the frozen schema and `domain/events.py`.
- `ProtocolValueError` reason codes include: `duplicate_object_key`, `float_forbidden`,
  `integer_out_of_safe_range`, `invalid_utf8`, `lone_surrogate`, `noncanonical_integer_string`,
  `nesting_too_deep`, `unsorted_set_field`, `duplicate_set_member`.

The schema catalog (`protocol/schemas.py`) has two orthogonal enums. `SchemaKind` is the broad
runtime category `request_result|event|config|version_manifest`.
`SchemaArtifactRole` is the exact release/packaging role:
`common-value`, `MCP input`, `MCP output`, `persisted-envelope`, `event-envelope`,
`event-payload`, `configuration`, `finding`, `provider-judgment`, `semantic-provenance`,
`receipt-document`, `privacy-policy`, `outbound-case`, `privacy-audit`, `setup-contract`,
`local-control`, `service-status`, or `version-report`. `SchemaDocument` contains both
`schema_kind` and `artifact_role: SchemaArtifactRole`; neither value is inferred from the other.
The reviewed `schemas/manifest.json` owns the closed path-to-artifact-role mapping, and catalog
loading fails closed on an unknown or path-incompatible role.

Catalog loading is lazy in short-lived clients (issue #1083). Until a process builds the full
catalog for another reason (`load_schema_catalog()`, `schema_document_for()`, or a rejection's
diagnostic), `validate_schema_instance` parses only the requested schema and its transitive `$ref`
closure. The rest of the catalog's checks stay eager: the manifest, the exact file set, and every
member's byte length and SHA-256.

- Each loaded document passes the full catalog's own per-document checks, and every reference in a
  closure resolves to the same contents as in the full registry.
- Every rejection, and anything the lazy catalog cannot decide exactly, takes the full-catalog path.
  Error codes and `SchemaInstanceInvalid` fields are therefore unchanged.
- `client_handshake` loads the four control-envelope closures before writing the hello, where the
  full catalog used to be built.
- The service calls `use_full_schema_catalog()` before it serves and keeps the full catalog.

One boundary is narrower than before. A member outside every loaded closure whose bytes still match
the manifest digest, but are not canonical or carry a wrong `$id`, is no longer refused by a hook.
The service still refuses it, and so does any later full load.

The independent exhaustive path-to-`SchemaKind` map is: `events/* -> event`,
`config/* -> config`, `version/* -> version_manifest`, and
`common/*|operations/*|findings/*|receipts/*|privacy/*|service/* -> request_result`. The manifest
records both typed values and the catalog re-derives each from its own map. These prefixes exhaust
every member of `schemas/manifest.json` (the reviewed manifest, not this prose, owns the count);
no `support_manifest` kind or support-manifest schema exists.

## 5. Coverage (`protocol/coverage.py`)

Frozen dataclass `Coverage` with six dimensions + `known_gaps: tuple[str, ...]`:

| Field | Enum name | Ordered values (weakest → strongest where ordered) |
|---|---|---|
| `publication_channels` | `tuple[PublicationChannel, ...]` | sorted-unique set drawn from `cooperative_mcp`, `local_cli`, `codex_jsonl_import`, `hook_observed`, `engine_derived`, `human_import` |
| `authorship_assurance` | `AuthorshipAssurance` | `self_asserted` < `harness_observed` < `locally_authenticated` < `service_authenticated` < `cryptographically_attested` (reserved) |
| `artifact_observation` | `ArtifactObservation` | `published_only` < `import_observed` < `hook_observed` < `content_captured` < `artifact_verified` < `independently_reproduced` |
| `evidence_immutability` | `EvidenceImmutability` | `mutable_reference` < `metadata_only` < `content_digest` < `immutable_snapshot` < `independently_reproduced` |
| `ledger_freshness` | `LedgerFreshness` | `unknown` < `redacted_gap` < `partial` < `stale_after_material_change` < `current` |
| `check_types` | `tuple[CheckType, ...]` | sorted-unique set drawn from `none`, `deterministic`, `semantic_model_derived` |

Functions: `weakest(a: Coverage, b: Coverage) -> Coverage` (component-wise minimum for ordered
dimensions; set union for `publication_channels`, `check_types`, and gaps);
`coverage_for_channel(channel) -> Coverage` (conservative singleton defaults), plus the sole
closed `coverage_from_json`/`coverage_to_json` codecs. An individual
accepted event still has one singular `publication_channel`; aggregation into `Coverage` uses a
singleton tuple. The `none` check type is canonical only when it is the sole member and is removed
when either real check kind is present.
Coverage stores exact built-in tuples, exact enum members, and exact built-in gap strings;
constructor validation is left-to-right in declared field order. The two helpers require exact
`Coverage`/`PublicationChannel` inputs and map wrong runtime types to `invalid_coverage_value`
rather than accepting spoofed `__class__` or duck-typed objects.
No arithmetic averaging exists anywhere.

`known_gaps` remains an exact sorted-unique set with a 64-code wire bound. The ledger append
boundary owns the corresponding task-global receipt-capacity invariant: before committing a
proposed batch, it freezes the healthy-storage local-check case for the proposed projection and
unions its gap codes with the applicable check coverage, receipt applicability gaps, and every
current retained finding coverage selected by the receipt successor rule. Exactly 64 distinct
codes is admitted; a 65th distinct code rejects the whole batch atomically as `LIMIT_EXCEEDED`
with `component=receipt_coverage`, `count`, and `limit=64`. Duplicate codes do not consume extra
capacity, and comparison/order is ASCII byte order. No event, operation result, writer advance, or
projection change from the rejected batch becomes durable. This admission failure reports a
representational capacity limit, never caller-malformed `INVALID_REQUEST`, and it never truncates
or lexically selects material gap identities. `weakest`, codecs, schemas, and receipt validation
therefore retain their exact 64-code rule; append admission prevents a newly accepted healthy
task state from requiring an unrepresentable receipt fold.

## 6. Actor and client types (`protocol/models.py` boundary; `domain/values.py` internal)

- `ActorType`: `human`, `harness`, `logical_agent`, `model_backed_worker`, `delegated_subagent`,
  `yoetz_engine`, `importer`.
- Boundary: `ActorAssertionModel(actor_id, actor_type, display_name?, asserted_by?)`;
  `ClientInfoModel(kind: codex_cli|cooperative_agent|yoetz_cli|test_client|importer, version,
  integration: cooperative_mcp|local_cli|codex_jsonl_import)`. `cooperative_agent` is the
  transport-neutral value every harness without a first-party FinishUP integration uses; it is valid
  with `cooperative_mcp` or `local_cli` and is the honest identity for any MCP host FinishUP has not
  separately profiled. `codex_cli` is not a generic agent token and may be sent only by a client
  matching an installed Codex capability profile (ADR-005). A distinct `kind` records provenance
  only: assurance derives from the integration channel, so no `kind` value strengthens or weakens
  `Coverage`, and adding a first-party harness later is a `kind` addition, never a coverage change.
- Domain: `Actor(actor_id, actor_type, assurance)` — assurance is server-assigned, never copied
  from the caller.
- Domain `Frontier(sequence: int, head_digest: str)` is the one frontier type. Sequence zero is
  `Frontier(0, "genesis")`. Boundary models serialize only the sequence string where the public
  schema intentionally does so; the application resolves that sequence to its unique accepted head
  digest before creating a domain value. Ports MUST import this type and MUST NOT define a second
  `Frontier` with renamed fields. `frontier_from_json` and `Frontier.as_wire` are its sole closed
  object codecs; both enforce the zero/genesis and positive/SHA-256 identity.
- `SubjectStateRef(tree_digest?, diff_digest?, described_state?)` binds a claim/action/result to
  observed artifact state. `described_state` is explanatory only and never participates in
  deterministic equality, freshness identity, or request commitments.

## 7. Event families (`domain/events.py`, schema version `1.0.0` unless noted)

`session_opened`, `session_resumed`, `plan_published`, `obligation_published`,
`assignment_recorded`, `decision_recorded`, `action_recorded`, `result_recorded`,
`evidence_recorded`, `claim_recorded`, `plan_revised`, `finding_recorded`, `response_recorded`,
`redaction_recorded`, `check_recorded`, `receipt_recorded`.

The shared event-draft schema is a structural union, not an authorization grant. Ordinary
`cooperative_mcp|local_cli` `publish_work` admits only plan, obligation, assignment, decision,
action, result, evidence, claim, and plan-revision work families. The trusted Codex import path
admits only its mapped action/result/evidence families plus opaque unknown events. Lifecycle,
finding/check, response, and receipt families enter through `start`, `check`, `respond`, and
`receipt`; redaction is reserved to the trusted maintenance path. A known family outside its row
fails before object staging with `event_family_not_admitted`; caller actor/client tokens never
widen the matrix.

The released `event-draft/1.0.0`, `opaque-unknown-event-draft/1.0.0`, and
`publish-work-request/1.0.0` bytes stay frozen. Claim correction is authorable only through the
additive `event-draft/1.1.0` and `publish-work-request/1.1.0` schemas; the latter selects the v1.1
draft union while preserving the public request body's `schema_version: "1.0.0"`. MCP descriptors
select that catalog version for `publish_work`, and local service control `2.4.0` carries it. The
frozen v1.0 draft remains forward-compatible and classifies the new pair as opaque; v1.1 recognizes
it exactly and excludes it from its opaque branch. The manifest-bound handshake supersedes a stale
2.3.0 service before publication, so the old runtime never gets to interpret that opaque shape.

Shared domain types: `EventDraft` (client-shaped, pre-acceptance), `AcceptedEvent` (the canonical
structural envelope frozen by `domain/events.py` plus decoded payload handle), `UnknownEvent`
(opaque preserved,
`projection_status = "unknown_unprojected"`). Payload dataclasses are named
`<FamilyPascal>Payload`, e.g. `ObligationPublishedPayload`, except
`FindingRecordedPayload = Finding`, the explicit alias that prevents a second finding codec.

`domain/events.py` also owns the exact support records `RequestedItem`, `ObligationChange`,
`PolicyVersion`, `EventSchema`, `WriterChain`, `LedgerChain`, `PayloadRef`, and
`ProjectionLocator`, plus the event-only enums listed in that file. `ProjectionLocator` is the
runtime-only non-plaintext replay record `(schema, logical_key, canonical_payload_digest,
redaction_target_event_ids, redaction_target_object_ids)` captured atomically beside every
accepted event and never serialized into the 19-field accepted wire record. Known schemas use the
closed family key mapping; an unknown schema uses `logical_key=None`, empty target tuples, and the
same digest exposed on `UnknownEvent`. The durable SQLite sidecar has one row per accepted event;
schema identity, logical-key mapping, payload digest, and redaction targets must match the accepted payload or replay fails with
`invalid_projection_locator`. `WriterChain.sequence` and `LedgerChain.ingestion_sequence` are
positive signed-64-bit domain integers rendered as decimal strings. `PayloadRef.plaintext_size` is
a bounded domain integer rendered as a JSON integer, not a decimal string.

Object-only replay uses the existing accepted-envelope fields; it does not widen that locator or
wire record. Every `payload_ref.object_id` identifies its envelope's event ID. For exact-known
`evidence_recorded`, `artifact_refs` is exactly empty when `captured_object_id` is absent and exactly
the singleton `(captured_object_id,)` when present. For `redaction_recorded`, `artifact_refs` is
exactly the payload/locator target-object tuple. For `receipt_recorded`, `artifact_refs` is exactly
the singleton `(receipt_object_id,)`. These typed-ID mirrors plus locator logical keys
are sufficient to rebuild the pure reverse `ReplayIndex` after payload deletion without retaining
content, paths, URLs, or human redaction text.

The supported payload dispatch map is keyed by the complete `EventSchema`. All sixteen families
decode at `1.0.0`; `evidence_recorded/1.1.0` and `evidence_recorded/1.2.0` are also exact-known.
Every other syntactically valid pair is preserved as `UnknownEvent`. A malformed payload for an
exact supported pair is invalid and never falls back to opaque handling.

Both ledger-record variants carry the complete accepted-envelope fields. `UnknownEvent` replaces
the typed handle with `JsonValue | None` and adds `canonical_payload_digest` plus the fixed
projection-status token; it does not omit causal parents, redaction, artifact refs, or evidence
refs. The envelope's historically named `evidence_refs` field is the exact sorted-unique
`EvidenceId | ResultId` union used by response/result mirrors; each ID kind remains distinguishable
by its canonical prefix and by the durable `event_refs` index. Full accepted-record JSON includes
`entry_digest` and matches the accepted-event schema.
The entry-digest preimage is that exact record with only `entry_digest` removed; decoded payload
handles and unknown-only adjacent metadata appear in neither JSON view.

Key payload fields (minimum; full shapes in `src/finishup/domain/events.py`):

- `plan_published`: `plan_version`, `summary`, sorted-unique `obligation_refs`, optional
  `scope_exclusions`, and optional `no_obligations_reason`
  (`no_material_change|single_atomic_change|exploratory_scope_unknown`). The reason is valid only
  when `obligation_refs` is empty.
  The first event starts the plan chain. A later `plan_published` is a full append-only scope
  restatement only when its version is exactly the current version plus one; it replaces the
  effective refs and empty-scope reason. A duplicate root or version gap makes scope unreadable.
- `obligation_published`: `obligation_id`, `description`, `evidence_expectation`, optional
  `acceptance_criteria`, `requested_items`, `source_refs`. Each requested item is
  `{item_kind, value}` with `item_kind` `url|file|command|change|source`.
- `obligation_published/1.1.0` (issue #1002, ADR-033 decision 2): the same fields; a requested
  item is `{item_kind, value, role?}`, `item_kind` adds `directory`, and the optional closed
  `role` is `input|output` (`RequestedItemRole`), admitted only on `file` and `directory` items.
  Absent `role` keeps the 1.0.0 meaning (a `file` item may be an input or an output). `status`
  adds `acknowledged_not_done` (`ObligationStatus.ACKNOWLEDGED_NOT_DONE`) with
  `acknowledged_not_done_reason` (1..4096 UTF-8 bytes, non-blank), required for that status and
  forbidden otherwise; `resolution_evidence_refs` stays reserved to `resolved`. One rule
  (`domain.events.obligation_schema_admits`, ADR-041): 1.0.0 refuses a role, a `directory` item
  and `acknowledged_not_done`; 1.1.0 is a superset that admits every payload, including a plain
  one. FinishUP itself drafts the lowest admitting version (`obligation_schema_version`: 1.1.0 iff
  one of those is present), so released `1.0.0` stays admitted and byte-identical. Ledgers that
  hold a plain 1.1.0 obligation do not replay on a build older than this rule. The reducer keeps the last effective status among
  `open`, `acknowledged_not_done` and `resolved` (meaning fields must repeat; a `resolved`
  obligation may be reopened `open` or acknowledged, never re-resolved in place; ADR-041); consumers treat `acknowledged_not_done` as not resolved, like `open`, and status
  `view=obligations` (status-result 1.4.0) shows the status and `acknowledged_not_done_reason`
  under the `obligation_text` category, like the description. The unreleased event-draft 1.2.0 (and so `publish-work-request/1.2.0`) admits
  the pair in place and excludes it from its opaque branch. `role: input` items never yield
  requested-output facts; `role: output` items count as written; a `directory` holding no file is
  absent. `finishup.kernel.task_facts.declared_output_items(projection)` returns
  `(obligation_id, item_index, item_kind, value)` for every effective obligation's `file` or
  `directory` item with `role: output`, sorted by obligation id (ASCII) then index.
- `action_recorded`: `action_id`, `action_kind` (`command`|`edit`|`research`|`review`|`other`),
  `description`, optional `command`, `subject_state` (see SubjectStateRef below).
- `result_recorded`: `result_id`, `action_id`, `outcome` (`success`|`failure`|`partial`|
  `unknown`), optional `exit_status`, `subject_state`, `evidence_refs`.
- `evidence_recorded`: `evidence_id`, `strength` (mirrors `EvidenceImmutability`), `reference`
  (mutable ref) and/or `captured_object_id` + `content_digest`, `observed_at`, `evidence_kind`.
  New digest-bearing records require `digest_binding` with closed `subject`,
  `content_availability`, `byte_count`, and `provenance`.   Kind/subject compatibility is closed;
  `test_result` cannot bind `source_diff`. Schema `1.1.0` admits `caller_asserted`,
  `approved_check`, and `import_observed`; additive schema `1.2.0` also admits
  `observation_captured`. Ordinary publication can assert only `caller_asserted`; approved-check,
  import, and observation provenance are reserved to their authenticated authors/channels.
  `observation_captured` requires the observation coordinator (`harness_observed` on
  `hook_observed`) and never means verified or independently reproduced. It has exactly two
  shapes: captured bytes (`immutable_snapshot`, `captured`, content-captured coverage) and, since
  #1013, an observed image digest (`content_digest`, `digest_only`, subject `artifact_bytes`, no
  captured object), which can never pose as captured content. Schemas `1.0.0` and
  `1.1.0` remain exact-readable; an untyped legacy digest remains unknown rather than inheriting a
  subject from prose.
- `claim_recorded/1.0.0`: frozen `claim_id`, `claim_kind` (`completion`|`material`),
  `statement`, `supporting_refs` (evidence/result/obligation IDs), optional `subject_state`,
  `obligation_refs`, and `disputes_refs`. Its historical rule remains: citing a `failure` or
  `partial` result on a completion claim's `supporting_refs` discloses that limitation rather than
  creating `evidence_does_not_support_claim`. An `unknown` result still mismatches.
- `claim_recorded/1.1.0`: the same fields plus required `limitation_refs` (partial/failed result
  IDs) and `supersedes_claim_refs` (prior effective claim IDs), using empty arrays when neither
  applies. Admissible support stays in
  `supporting_refs`; non-success results never do. A replacement uses a fresh claim id, same claim
  kind, overlapping declared obligation scope for each nonempty target, and the complete relevant
  limitation set. An empty-scope target may be explicitly superseded by empty or populated scope;
  no scope is inferred from supporting refs. New ordinary v1.1 completion publications must
  explicitly send `obligation_refs`; intentional `[]` cannot have obligation support and remains
  coverage-incomplete. These admission guards do not invalidate history or committed retries. Replay
  rejects missing/already-replaced targets, disjoint scope, wrong result outcomes, irrelevant
  limitations, or incomplete linkage before append. A limiting result must predate the claim and
  have an action whose obligation scope overlaps the claim; an unscoped side remains task-wide, and
  a result whose action record is absent or tombstoned is task-wide relevant and linkable on the
  same reading. `limitation_refs` requires every relevant `partial`/`failure` result that is still
  live under the observed-failure supersession rule below, and also accepts a relevant `unknown`
  one, which is the only field a v1.1 claim has to disclose an `unknown` limitation; naming it
  never reclassifies it as a typed partial or failure.
- `plan_revised`: `plan_version`, `supersedes_plan_version`, `reason`, `summary`,
  `obligation_changes`, and optional `no_obligations_reason` using the same closed values. A
  revision restates the effective current declaration: omission clears an earlier reason, and a
  present reason is valid only when applying the revision leaves zero effective obligation refs.
- `response_recorded`: `finding_id`, `finding_frontier`, `disposition`
  (`acknowledged`|`provenance_disputed`|`rejected`|`waived`), optional `reason`, optional
  `waiver_scope`, `waiver_expiry`, `evidence_refs`. `provenance_disputed` contests the finding's
  authorship or provenance premise without rejecting its conclusion or resolving it.
- `SubjectStateRef`: optional `tree_digest`, `diff_digest`, `described_state` — binds evidence
  and claims to repository/artifact state for freshness checks.

**Observed-failure supersession (#909).** `kernel/observed_failures.py` owns one predicate that the
claim-revision replay invariant (`limitation_refs_complete`), work-integrity `failed_work_omitted`,
research-evidence `material_limitation_omitted`, observation-advice `failed_command_unresolved`, and
the receipt builder all read. `ObservedFailureState` is exactly `live`, `superseded`, `rerun`, or
`historical`. `classify_observed_runs(runs)` takes `ObservedRun(ref, position, outcome, identity,
edit)` values and, for each failed or partial run, returns `superseded` when a later run with the
same identity succeeded, else `rerun` when a later run with the same identity has a limiting
failure or partial outcome (only the latest limiting run of a command identity can be `live`), else
`live`. An unknown outcome does not certify repair. Edits never retire a failed verification, and a
run without an identity remains live. Explicit acknowledgement discloses that failure without
making it green. `observed_failure_states(projection, observed_event_ids, through=frontier)` applies it
to the readable results recorded no later than `through` whose source events are service-stamped
hook observations (`is_observed_run_record`: observation-coordinator authorship on the
`hook_observed` channel; in a frozen case, `hook_observed` in the ref's coverage channels). A
command action's identity is `command_identity(command)`: the `hmac-sha256:` commitment in an
`omitted:<commitment>` command, never a plain `sha256:` digest and never `omitted:structural`; an
edit is an observed `edit` action. Only observed rows take part on either side, so cooperative
results keep their exact disclosure duty. `ReplayIndex.observed_event_ids` carries the provenance
into replay. A `live` observed failure's `failed_work_omitted` adds the `observed_failure_live` fact
naming its result and action and a sentence pointing at `status view=results`; research-evidence's
copy of the same (claim, result) omission is dropped when work integrity reported it
(`_collapse_failed_work_overlap`), so one omitted failure is one finding. The receipt's limitations
section names superseded, rerun, legacy historical, and `limitation_refs`-disclosed observed
failures once, bounded to ten ids per clause. An observed edit changes the state under test but is
not a covering verification, so a failure followed only by an edit stays `live` until the same
command is rerun or the claim explicitly acknowledges it. An edit the harness sees only as a
shell command (a heredoc written through `exec_command` or `Bash`) is a command, not an observed
edit, and follows the same rule for failure supersession. For the stale-verification rule such a
command counts as an edit when it visibly writes the workspace (`write_scope: workspace`, ADR-045).

`reason` MAY be omitted for `acknowledged` and MUST be non-empty for `provenance_disputed`,
`rejected`, or `waived`.
Waiver-only fields are forbidden on other dispositions. `finding_frontier` is always the full
domain `Frontier`, even when the public request supplied only its canonical sequence string.
`respond` accepts any in-chain `finding_frontier` at or after the frontier that first carries the
finding's record: the check result frontier, a status finding item's `finding_frontier` when it
carries one, or simply the current status frontier. Only a frontier before that record (such as the
finding's `subject_frontier`) or outside the current chain is rejected (`finding_not_in_prefix`),
so answering a finding never requires a historical frontier search (#911).

`WaiverScope` has one v0.1 value, `finding_only`, and serializes with the exact finding ID/frontier
already present on the response. The nominal enum is owned by `domain/findings.py`; broader
subject/obligation/project waivers are deferred. A waiver
is accepted only from an interactive `local_cli` request constrained as a human and explicitly
confirmed at the prompt; MCP, importer, noninteractive CLI, and model-backed actors may acknowledge
or dispute provenance, and may reject with evidence, but may not waive. `waiver_expiry` may further
narrow that one-finding
scope. This is authorization policy, not a caller-asserted actor upgrade.
`ResponseDisposition` is likewise nominally owned by `domain/findings.py` and reused by event and
receipt records.

`CheckMode`, owned by `domain/events.py`, is exactly `deterministic_only`,
`semantic_if_configured`, or `semantic_required`. It is the one enum used by check requests,
`CheckRecordedPayload`, application orchestration, and renderers.

`CheckRecordedPayload` carries the exact required `coverage: Coverage` from the recorded
`RankedFindings`; reducers retain it in `latest_tested_state` and MUST NOT infer it later from the
visible finding IDs. `returned_finding_ids` is the unique ASCII-ascending set of those selected
IDs. Ranked presentation order lives on the check result's `findings` tuple and is reconstructed
after durable replay with the registered `rank_key`; the event field is not that order.

`CheckRecordedPayload.semantic_status` uses the single shared `SemanticStatus` enum:
`not_requested`, `not_configured`, `blocked_by_policy`, `blocked_forbidden_data`,
`classification_uncertain`, `awaiting_human`, `human_denied`, `approval_expired`, `succeeded`,
`refused`, `timeout`, `invalid`, `unavailable`, `late`, `stale`, `failed`. `late` means a provider
attempt returned after it lost lease/deadline authority;
`stale` means a once-valid result no longer matches the frozen frontier/dependency digest. These
states are distinct and there is no second `completed` spelling.

`awaiting_human` is the one **nonterminal** AI-powered review status. Under the per-request
confirmation posture, one exact prepared case is waiting on a local disclosure decision: the check
operation, AI-powered review job, and physical attempt stay open, no provider was reached, and no
verdict or completion-grade coverage exists yet. Approval resumes the *same* request, attempt,
provider request id, proposal, and case digest. The durable suspension lives in
`semantic_disclosure_waits` (bundle schema 5), which is one-use. A missing standing repository grant
stops earlier: only the check operation is suspended, before provider construction, job creation,
credential inspection, or dispatch. Bundle migration 0006 records
`operations.suspension_kind=repository_grant` transactionally on that exact operation; status reads
that durable discriminator and never reconstructs it from mutable current authority. The marker
clears only when that same operation resumes or terminalizes. While the marker is set, the operation
is not an active frozen-case barrier: observation-authored appends proceed, and same-request replay
re-installs the barrier when it reclaims the lease (issue #445). Only a successfully read, valid,
exactly bound `RepositoryPrivacyAuthority(grant_state="missing")` may create this suspension. An
unbound or mismatched route, missing commitment, closed coordinator, invalid or unavailable policy,
unavailable reconciliation capability, or activation/reconciliation failure is terminal
`blocked_by_policy/scope_not_authorized`, with no provider construction, job, attempt, dispatch, or
trusted-approval instruction. Neither suspension branch is committed as a terminal result.

Bundle restart recovery reconstructs the pending check operation, AI-powered review job, physical
attempt, and disclosure wait as one resumable state. Restoring only the wait marker is insufficient:
the attempt coordinator would have no job to reclaim and could not preserve the approved provider
request identity. A denial, expiry, stale-authority result, or cancellation terminalizes the job and
attempt first, then resolves the one-use wait; a crash between those writes recovers the terminal
job and finishes the wait cleanup without dispatching or minting a replacement attempt.

The agent-facing handoff preserves that state distinction. Both a missing standing repository grant
and a one-use `confirm_every_request` decision are nonterminal `awaiting_human` continuations bound
to the exact original check request id. The continuation kind distinguishes them: repository setup
has the fixed trusted CLI/TUI command `finishup --privacy` and no proposal id or expiry, while the
one-use decision carries its durable proposal id, expiry, and exact decision command. The caller
recovers either continuation through `status(view=operation)` or exact replay of the original
request and must never create a replacement check. Chat confirmation is never authority. Denial,
expiry, cancellation, stale authority, or incomplete local review remains pre-dispatch.

Every status is paired with one required closed `SemanticReason`, never prose or a renderer guess:
`deterministic_mode`, `deferred_before_first_edit`, `no_material_semantic_case`,
`provider_not_configured`,
`local_model_not_configured`, `network_egress_denied`, `channel_disabled`,
`provider_binding_not_authorized`, `scope_not_authorized`,
`content_category_not_authorized`, `policy_generation_revoked`, `never_send_detected`,
`secret_detected`, `classification_uncertain`, `human_approval_required`, `human_denied`,
`human_approval_expired`, `semantic_completed`, `provider_refused`, `provider_timeout`,
`response_schema_invalid`, `response_content_invalid`, `semantic_judgment_rejected`,
`credential_unavailable`, `endpoint_profile_unavailable`, `transport_unavailable`,
`provider_rate_limited`, `provider_quota_exhausted`, `retry_budget_exhausted`,
`audit_reservation_unavailable`, `receipt_persistence_unknown`, `deadline_authority_lost`,
`lease_authority_lost`, `frontier_changed`, `dependency_changed`, `route_semantic_ceiling`,
`case_capacity_exceeded`, `coordinator_failure`. `route_semantic_ceiling` is paired with `blocked_by_policy` when a strict
MCP process receives an AI-powered check request; it is a route-local ceiling, not a durable-policy
decision.
`protocol/models.py` owns both enum objects, the immutable exhaustive status/reason relation, and
its pair and final-provenance-binding validators. `domain/events.py`, `domain/findings.py`, and `ports/semantic.py` import those same
objects; the port owns only outcome conversion and may re-export them. `CheckRecordedPayload` and
`CheckResultModel` require the pair; predispatch outcomes carry no attempt provenance. A present
provenance record always repeats that same selected/final status and reason. Earlier late or
non-selected attempts remain attempt-audit rows and never replace the selected provenance.

`protocol/models.py` also nominally owns `ClientKind`
(`codex_cli|cooperative_agent|yoetz_cli|test_client|importer`) and `IntegrationKind`
(`cooperative_mcp|local_cli|codex_jsonl_import`) because `ClientInfoModel` is a dependency-root
boundary model. `domain/events.py` imports and re-exports those identical enum objects; it does not
redeclare them or create a protocol/domain import cycle.

`EvidenceKind` is `artifact`, `command_output`, `test_result`, `research_source`,
`import_report`, or `other`. A completed import publishes one ordinary `evidence_recorded` event
with `evidence_kind=import_report`, an immutable captured report object/digest, and its conservative
import coverage; this makes completion/gaps part of the same replayable ledger frontier without
adding a seventh workflow operation or an import-only event family.

## 8. Findings (`domain/findings.py`)

`CandidateFinding(kind, origin: deterministic|semantic_model_derived, priority: 1..3,
summary, detail, subject_refs, policy_id, policy_version, subject_frontier, coverage,
provenance)` is the ID-free pure-kernel value. `Finding` adds exactly one server-allocated
`finding_id` to a validated candidate.

`Finding(finding_id, kind, origin: deterministic|semantic_model_derived, priority: 1..3,
summary, detail, subject_refs: tuple[event/obligation/claim ids], policy_id, policy_version,
subject_frontier, coverage: Coverage, provenance: SemanticProvenance | None)`.

`FindingOrigin` is the nominal enum `deterministic|semantic_model_derived` and
`ResponseDisposition` is the nominal enum
`acknowledged|provenance_disputed|rejected|waived`; both are owned here.
`domain/findings.py` also solely owns the finalized, receipt-bound `SemanticProvenance` and its
schema-shaped `SamplingParams`, `TokenUsage`, `CostFields`, `SemanticDispatchKind`, and
`SemanticFailureClass` values
(`authentication|authorization|provider_outage|quota_exhausted|rate_limited|response_content|
response_schema|timeout|transport|unsupported_profile`). It imports the shared status/reason
enums and validator from `protocol/models.py`. `ports/semantic.py` owns only provisional
provider-attempt provenance and imports/re-exports the final type; it does not define another
`SemanticProvenance`.

The exact final provenance fields are provider/profile/version/model identities; prompt, schema,
policy, and privacy-policy digests; sampling parameters; latency; optional provider request,
usage, cost, and failure facts; AI-powered review attempt ID; dispatch kind; exactly one external
authorization or local-disclosure reservation; durable privacy-receipt ID; external request
commitment when applicable; and the validated terminal status/reason pair. The exact Python fields
and wire conversions are frozen in `domain/findings.md` and
`semantic-provenance-1.0.0.schema.json`; the append-only external-runtime extension is carried by
current `semantic-provenance-1.2.0.schema.json` and `runtime-attempt-evidence-1.1.0.schema.json`,
while the released `semantic-provenance-1.1.0.schema.json` and
`runtime-attempt-evidence-1.0.0.schema.json` remain readable. The
same append-only `1.1.0` carries the optional `fallback_from` object (issue #582) — `provider`,
`endpoint_profile_id`, `endpoint_profile_version`, `model`, `attempted_count`, `reason` —
present exactly when the declared fallback endpoint served the attempt; the top-level
provider/model/endpoint then name the fallback and `fallback_from` names the primary, its
physical attempts before engagement (zero when it could not be resolved), and its last closed
fallback-licensing or pre-dispatch reason. It travels unchanged into check results,
check-recorded events, findings, and JSON receipts.

`policy_digest` and `privacy_policy_digest` on `ProviderAttemptProvenance` and
`SemanticProvenance` are bound by the outbound gateway to the effective policy digest that
authorized the physical dispatch — the same value carried by `ApprovedOutboundCase.policy_digest`,
`EgressAuthorization.policy_digest`, and `EgressReceipt.policy.policy_digest`. A provider adapter
never asserts them. On a successful dispatch they are never placeholder or all-zero values.

A local candidate/finding forbids provenance. An AI-powered (model-derived) candidate/finding
requires receipt-finalized provenance whose status/reason is exactly
`succeeded/semantic_completed`; failed, refused, stale, late, invalid, timeout, or unavailable
attempt provenance remains valid check accounting but can never justify an AI-powered finding.

`finding_from_json`/`finding_to_json` and
`semantic_provenance_from_json`/`semantic_provenance_to_json` are the sole codecs. The finding
event alias delegates to them; no event, port, Pydantic model, or adapter owns a parallel dump.

Codex subscription-runtime attempts may carry a bounded `runtime_evidence.token_usage` object in
the current runtime evidence schema. It records one cumulative `total` snapshot as non-overlapping
`input_tokens`, `output_tokens`, and `total_tokens`, plus the `cached_input_tokens`,
`cache_write_input_tokens`, and `reasoning_output_tokens` counters for analysis. Cached input and
reasoning output are subsets and are never added again; cache-write input remains a separate
provider counter with no assumed arithmetic relationship. Repeated snapshots are replaced rather
than summed. Missing usage remains absent, and malformed or regressing matching snapshots leave a
closed `token_usage_invalid` diagnostic without invalidating an otherwise valid AI-powered judgment.
Only the exact active thread and turn are accepted, and no account identifiers or raw provider
notification body is retained.

Work-integrity finding kinds (`FindingKind`):
`completion_with_open_obligations`, `requested_item_never_attempted`,
`failed_work_omitted`, `claim_without_admissible_evidence`, `result_without_action`,
`action_without_result`,
`stale_evidence_for_changed_state`, `contradictory_claims_unresolved`,
`ledger_stale_or_incomplete`, `weak_or_stale_response` (flags a hollow or stale rejection/waiver
of a local finding; an AI-powered finding is advisory, so rejecting one never mints it — the next
review judges that rejection, issue #905).
Research/evidence-assessment kinds: `evidence_does_not_support_claim`, `diff_does_not_match_account`,
`material_limitation_omitted`, `questionable_finding_rejection` (flags a current hollow
rejection/waiver of a local finding).

Project coordination adds the local-only `coordination_overlap` kind under the
`coordination/0.1.0` runtime policy. It is generated from an admitted coordination projection and
is deliberately excluded from the external semantic case and the frozen
`provider-judgment-1.0.0` wire under D7. Adding it to an external provider requires a new
versioned provider contract; the historical 1.0 artifact remains unchanged.

Those two response predicates overlap on one case: a current rejection or waiver of a
local finding whose support is inadmissible under both packs' evidence criteria. Each pack
is a closed rule table that cannot observe the other, so both still report it. The check
composition layer resolves the overlap, dropping `weak_or_stale_response` only when
`questionable_finding_rejection` was actually produced for the same finding and response event in
the same run, so one response yields one actionable finding.

The collapse is keyed on the assessment research-evidence really emitted, not on re-deriving its
predicate. When that pack is deselected via `policy_packs`, excluded by scope, skipped as
materially unavailable, or fails, `weak_or_stale_response` stands, so a hollow rejection is never
lost to a pack that did not run. Selecting a single pack therefore yields that pack's own view.

The ownership partition is exhaustive and disjoint: the first ten kinds belong to the built-in
`work-integrity` pack (current version `0.2.0`), and the latter four belong to the built-in
`research-evidence` pack (current version `0.2.0`). `coordination_overlap` belongs to the local coordination runtime,
not either built-in pack. `semantic-review` is only a review-context / recipe label; it is not a
`PolicyPack` value and it never appears as `Finding.policy_id`.

Finding kind identifies the problem, not who detected it. The research-evidence pack may produce
the latter four as local checks, and an AI-powered reviewer may propose the same kinds. `origin`
alone distinguishes `deterministic` from `semantic_model_derived`; provenance rules follow origin,
not the kind token.

`FINDING_KIND_TRAITS` is the immutable exhaustive mapping below. The numeric priority is a
required serialized fact and MUST equal the row for the kind; `actionable` is derived and is not a
second wire field. `actionable=true` means the finding requests a concrete repair to the work or
its account; false means it reports a coverage/ledger limitation whose remedy is not safely
inferable from the frozen case.

| `FindingKind` | Required priority | Actionable |
|---|---:|:---:|
| `completion_with_open_obligations` | 1 | true |
| `requested_item_never_attempted` | 2 | true |
| `failed_work_omitted` | 1 | true |
| `claim_without_admissible_evidence` | 1 | true |
| `result_without_action` | 2 | true |
| `action_without_result` | 3 | true |
| `stale_evidence_for_changed_state` | 2 | true |
| `contradictory_claims_unresolved` | 1 | true |
| `ledger_stale_or_incomplete` | 3 | false |
| `weak_or_stale_response` | 2 | true |
| `evidence_does_not_support_claim` | 1 | true |
| `diff_does_not_match_account` | 1 | true |
| `material_limitation_omitted` | 1 | true |
| `questionable_finding_rejection` | 2 | true |
| `coordination_overlap` | 2 | true |

Ranking uses no prose or implementation-defined scoring. The evidence-strength bucket is the
lexicographic pair `(artifact_observation ordinal, evidence_immutability ordinal)` using the
weakest-to-strongest zero-based orders in §5. The coverage bucket is the lexicographic sequence
`(ledger_freshness ordinal, authorship_assurance ordinal, real_check_present)`, strongest first,
followed by fewer `known_gaps` first; `real_check_present` is 1 when `check_types` contains
`deterministic` or `semantic_model_derived`, otherwise 0. Publication-channel breadth and exact
gap/check-type identities are not strength scores.

The complete ascending `rank_key` is `(priority, -actionable, -artifact_ordinal,
-immutability_ordinal, -freshness_ordinal, -authorship_ordinal, -real_check_present,
known_gap_count, origin_ordinal, finding_id_bytes)`, where `origin_ordinal` is 0 for `deterministic`
and 1 for `semantic_model_derived`. Thus local findings precede AI-powered findings only after all
materiality,
actionability, evidence, and coverage facts tie, and unsigned ASCII `finding_id` bytes are always
the final tie-break.

`kernel/ranking.py` owns `CheckCompleteness = complete|coverage_incomplete|required_incomplete` and
`RankingContext(coverage: Coverage, completeness: CheckCompleteness)`. The application derives that
context from terminal check facts before ranking. Its coverage is the component-wise weakest
material coverage across the frozen case, every local-check assessment/basis and candidate,
AI-powered review dependencies/outcomes, every explicit unknown/redaction/freshness gap, and all
findings before capping. `required_incomplete` means a required local policy pack failed or a
material `semantic_required` path terminated without valid success; `coverage_incomplete` means
required checks completed but material coverage is missing/redacted/unknown/stale or an optional
requested AI-powered review path yielded no usable evidence; `complete` means required packs
completed with no material gap and AI-powered review work succeeded or was not required/not
material.

Verdict enum (`CheckVerdict`): `action_required`, `no_issue_detected`, `insufficient_coverage`,
`incomplete_check`. Never `pass`.

`RankedFindings` is exactly the frozen four-field value `(findings: tuple[Finding, ...],
suppressed_count: int, verdict: CheckVerdict, coverage: Coverage)`. `findings` is the ordered
selected set after the optional one-slot AI-powered-finding diversity rule, not necessarily the
ordinary top-N prefix. `coverage` is always the full `RankingContext.coverage`; suppression or slot
replacement never strengthens it. Verdict precedence is `required_incomplete -> incomplete_check`,
else either closed completion-scope gap -> `insufficient_coverage`, else any selected actionable
finding -> `action_required`, else `coverage_incomplete -> insufficient_coverage`, else
`no_issue_detected` with an empty selection.

`ReceiptConclusion`, owned by `domain/receipts.py`, is exactly
`no_unresolved_deterministic_findings`, `unresolved_findings_remain`, or
`insufficient_coverage`. It is deliberately non-isomorphic with `CheckVerdict`: receipts derive
from projection facts and coverage rather than copying a prior check token. At the same unchanged
subject frontier the required correspondence is `action_required -> unresolved_findings_remain`,
`no_issue_detected -> no_unresolved_deterministic_findings`, and
`insufficient_coverage -> insufficient_coverage`; `incomplete_check` maps to
`unresolved_findings_remain` when any actionable finding remains unresolved at that frontier,
otherwise to `insufficient_coverage`. Ordinarily an `insufficient_coverage` check has no selected
actionable finding. The two closed completion-scope gaps are the narrow exception: selected findings
remain visible, but the gap dominates both the check verdict and receipt conclusion because empty
completion scope cannot support an action-required completion verdict.
A clean conclusion also needs every policy execution complete: `run/completed`, or
`skipped/not_applicable` on the whole case (no root of that pack's kind exists; #986), never
`scope_excluded`, `material_unavailable` or `failed`; and only gaps in
`kernel.deterministic_scope.CLEAN_COMPATIBLE_GAPS` (ADR-033 amendment of 2026-10-07), where a
member of `HOST_OBSERVATION_GUARDED_GAPS` counts only if the applicable check's own coverage
carried it. A full check's `complete` completeness uses the same list
(`full_check_gaps_clean`), with those host members only when `commands_complete(totals)`.

`domain/receipts.py` owns the exact schema-shaped `ReceiptDocument`, `ReceiptVersionSlice`,
policy/schema version entries, obligation/response/gap/redaction records, and canonical sections. It
owns receipt-only enums; response disposition and waiver scope reuse `domain/findings.py`, and the
boundary `ReceiptRedactionProfile` reuses `protocol/models.py`. The document field inventory is
exactly the receipt-document schema, including `suppressed_finding_count`, and it has no post-append
result frontier. An applicable AI-powered check contributes its selected `semantic_provenance`,
including bounded per-attempt token usage; local-only or historical receipts omit that optional
field so their prior bytes remain unchanged. The receipt provenance represents the applicable
provider result; usage for failed, expired, or late physical retries remains in the durable
AI-powered review attempt ledger and internal accounting, rather than being invented into that
public provenance.

`receipt_document_from_json`/`receipt_document_to_json` are the sole document codecs.
`render_receipt_compact(document) -> str` returns one bounded string; there is no v0.1
`ReceiptRender` wrapper. `receipt_weakest_coverage` folds the top-level coverage with every carried
finding coverage using `coverage.weakest`; every explicit receipt-gap code must also occur in the
top-level known-gap set, and the fold must equal that top-level coverage.

The completed check's `review_input_manifest` is metadata-only and remains the authority for what
the reviewer received: its `phase` (`composed` or `provider_bound`), each section's distinct
status, digest, revision, byte count, and bounded omission tokens are preserved. The shared
`domain.review_input_render` projection carries those facts through CLI, MCP, and TUI check views.
Receipt JSON keeps the released receipt-document schemas closed: the same metadata is carried in
the existing `limitations_and_coverage.coverage_note`, which the markdown and text renderers
project, while a missing `coverage_note` keeps historical receipt bytes unchanged. `missing_for_assessment`
remains a check limitation and renders its closed availability classification on the check and
receipt surfaces; it never becomes a finding or a clean-review claim.

Shared structural gap codes for optional AI-powered relevance review (distinct families):

- `optional_semantic_review_blocked_by_policy` — blocked before dispatch by network-egress policy;
- `optional_semantic_review_registration_drift` — the explicit Codex strict route ceiling blocked
  this process while the durable applied-route record says the last install applied the policy
  route. The disagreement is the whole claim: a strict route reached outside the install ceremony
  is a legitimate owner action, so the gap offers the recovery rather than asserting a stale
  process. Generic, Claude, and Cursor serving identities cannot be attributed to that Codex
  record. Carried alongside the ceiling gap above, never instead of it, so the terminal
  status/reason/provenance binding is unchanged;
- `semantic_review_not_configured` — evaluator/provider not configured;
- `semantic_relevance_review_not_run` — evaluation failed/timed out/unavailable without a clean pass.
  When the applicable check's `semantic_reason` is `coordinator_failure`, the limitations section
  names that fault inside FinishUP in a fixed sentence (issue #1077). The gap code is unchanged.
  JSON carries the sentence in the section body; markdown and text carry it in `human_text`;
  the compact sentence, the CLI JSON receipt line, and the MCP receipt summary repeat it;
- `semantic_review_not_requested` — local-only check; AI-powered review was never requested.
  It bounds the receipt conclusion unless the applicable check recorded
  `semantic_route_required: false` (issue #986, ADR-033 amendment of 2026-10-08): then the check's
  route did not require AI-powered review and the code is a disclosure only. A check that asked
  for `deterministic_only` on such a route records no such code at all (issue #1041): it ran the
  checks requested, and readers do not re-derive the code from its `not_requested` status. A
  review the round stopped (`semantic_review_skipped_insufficient_packet`) and every check an
  older build wrote keep the code they recorded.

`semantic_route_required` (optional boolean on the unreleased `check-recorded` and `check-result`
1.4.0) records whether the check's route required AI-powered review: the check asked for
`semantic_required`, or, on the policy route, the effective verification policy is `semantic:
required`. An explicitly deterministic-only route (the strict MCP route) did not require review
unless the check asked for it; a strict process with Codex registration drift (#537) follows the
policy (issue #1021, ADR-040). Writers emit it only as `false`; a requiring route omits it, so those checks and
every check an older build wrote keep their bytes and the blocking default.

**Admitted outside-workspace input roots (issue #1082, ADR-009 amendment of 2026-10-16).**
`PrivacyPolicy.admitted_input_roots` is a sorted tuple of at most `MAX_ADMITTED_INPUT_ROOTS` (8)
absolute directories (`admitted_input_root_valid`, `validate_admitted_input_roots`: normalized,
no hidden component, never `/` and never beneath the refused system trees). Privacy-policy wire
1.2.0 carries it as the optional `admitted_input_roots` array, written only when non-empty
(`policy_field_omitted`), so every existing policy, meet and receipt digest is unchanged; 1.0.0
and 1.1.0 refuse it. Composition (`_composed_input_roots`): between the installation and a
repository row the repository row decides; any other composition keeps the intersection; the meet
identity names the roots only when there are some. The diff vocabulary gains
`("global", "admitted_input_roots")` with `dir:<root>` labels, rendered "Directories outside the
workspace read as task inputs" under "Information disclosed"; adding a root widens, removing one
tightens. `finishup privacy input-roots add|remove|status` (`privacy_setup.run_input_root_change`,
`admitted_root_from_path`, `input_roots_candidate`) are the owner surfaces; add refuses
`input_root_invalid`, `input_roots_limit`, `local_terminal_required` and, without a grant,
reports `repository_privacy_grant_missing`. The terminal interface shows
`PrivacyPosture.admitted_input_roots_summary`. The service passes
`_outside_input_reader(policy.admitted_input_roots, (bundle, state))` to
`capture_check_time_change` as `outside_reader` (`OutsideInputReader`, called as
`(values, room, workspace)`) only when a root is admitted and `carries_task_inputs` holds; it reads
with `read_outside_inputs(roots, values, limit=room, excluded=(workspace, bundle, state))`.
`_with_outside_inputs` offers it only task-declared candidates (never `verification_paths`) and
rechecks every returned path against the workspace, case-folded. The reader opens each root one
component at a time from `/`, trusts a directory or file only when the service user or root owns
it and `writable_by_others` is false (a sticky directory excepted), and refuses the excluded
directories by device and inode at every level (PR #1086 review R1-02, R1-03, R1-05, R1-07).

**Per-task review mode (ADR-049).** A task (a "conversation" in the code: one task and its
sessions) switches between local checks only and AI-powered review with one
`decision_recorded` **1.1.0** draft carrying the required `review_mode: "local" | "ai_powered"`
(`ReviewMode`, `DECISION_REVIEW_MODE_SCHEMA_VERSION`); 1.0.0 refuses the field, and a decision
rides 1.1.0 iff it carries it, so plain decisions keep their 1.0.0 bytes. Ordinary
`cooperative_mcp|local_cli` `publish_work` admits it (event-draft 1.2.0). The owner's setting is
`PrivacyPolicy.conversation_review` (`ConversationReview`: `local_only`, `local_owner_approval`,
`local_agent_opt_in`, `ai_powered`; privacy-policy wire 1.2.0, written only when set, so every
existing policy, meet and receipt digest is unchanged; `effective_conversation_review` reads an
unset field as `ai_powered` where the inference channel is on and `local_only` where it is off).
The diff vocabulary gains `("global", "conversation_review")`, rendered "Tasks and AI-powered
review" in the Authorization group, ordered after `channel.preview_required`; a wider value is a
widening, a narrower one a tightening. Composition: the repository row's explicit value decides,
the installation value is only the default, any narrower composition keeps the setting that needs
more of the owner. `local_owner_approval` makes every LLM-inference dispatch under that policy
preview-required (`awaiting_human`, the `decide-disclosure` continuation). An explicit
`local_only` refuses `semantic-review` egress at the gateway (`egress.conversation_review_refuses`,
inside `semantic_policy_refusal` and again after the pre-dispatch policy refresh:
`blocked_by_policy` / `policy_denied`). A repository-bound `privacy_propose_policy` never widens
the machine member's `conversation_review` (`privacy_policy._machine_conversation_review`): an
explicit row value stays; an unset row whose inference channel the proposal turns on takes
`narrower_conversation_review(candidate.effective_conversation_review, local_agent_opt_in)`; a row
already sending stays unset. `build_candidate_policy(..., first_grant=True)` (the chat grant path
passes the snapshot's `grant_state == "missing"`) starts the setting at
`_first_grant_conversation_default` (a first grant without network egress records an explicit
`local_only` where the composed policy carries a setting, and none where nothing is inherited).
`ai_review_available` also requires the repository's own grant
(`repository_authority(scope).grant_state == "granted"`). `run_privacy_setup(...,
ai_review_add_on_when_hybrid=True)` (`finishup --privacy`) switches to the add-on listing where
`privacy_setup._agent_opt_in_needs_ai_recipes` holds (reviewer bound; first grant, or effective
`local_agent_opt_in` / `local_owner_approval`). `run_conversation_review_change` walks
`run_privacy_setup(conversation_review=..., ai_review_add_on=True)` for any setting but
`local_only` where the repository has no grant (`local_terminal_required` without a terminal).
`kernel/review_mode.py` owns `ReviewModeSwitch(event_id, sequence, mode, authority)`,
`review_mode_switches(projection)` (unredacted, unsuperseded, ledger order),
`ConversationReviewContext(setting, ai_review_available, setting_explicit)`,
`conversation_review_mode(...)` / `conversation_review_mode_from_switches(...)` →
`ConversationReviewMode(mode, requested, setting, switches, local_reason)` (properties
`driven_by_switch`, false for a switch to local under `ai_powered`, and `local_by_choice`, never
under `ai_powered`) with `local_reason` in `conversation_default`, `switched_to_local`,
`owner_local_only`, `route_local_only`, `review_disabled`, `ai_review_not_set_up`; the resolver
takes `review_enabled` (false where the verification policy is `disabled`).
`Application.conversation_review_reader` / `ServiceReadyContext.conversation_review_context`
supply the context (`None` in embedded and test compositions: checks keep the released
behaviour; a reader that raises makes a check that names no mode fail closed to local checks with
no recorded mode). `kernel/closure_readiness.semantic_review_used(records)` is the shared "already
used AI-powered review" fact: a `final_review: true` check that names no mode, in such a task now
running local, runs as its own request. `check_recorded` 1.4.0 and `check-result`
1.4.0 carry optional `review_mode` (`CheckReviewMode`: `mode`; `source` =
`conversation_default` | `conversation_switch` | `check_request`; optional `local_reason` =
`owner_local_only` | `route_local_only` | `review_disabled` | `ai_review_not_set_up`, only on
`mode: local`; a recorded `local_reason` makes the closing review current;
`switch_event_id` exactly when `source` is `conversation_switch`). It is absent where the setting
could not be read, and where the owner's policy predates the setting and the task recorded no
switch (the upgrade rule: those checks keep their released behaviour and bytes). A local task's
check that names no mode runs `deterministic_only` and records `semantic_route_required: false`.
`status-result` 1.4.0 carries optional `review_mode` (`mode`, `requested`, `setting`,
`setting_explicit`, `ai_review_available`, optional `local_reason`, `switch_event_id`,
`switch_sequence`), read from
the head projection on the serving route. Closure readiness (`execute_status`,
`current_closure_readiness`) passes `semantic_review_required` false for a task that runs local by
an explicit setting or its own switch (`_task_local_by_choice`, never under `ai_powered`). The
receipt's `limitations_and_coverage` body ends with the review-mode sentences: "Review mode
switches recorded for this task: ..." naming each switch's sequence, event id, recorded actor
(`recorded by <actor_id> (<actor_type>, <assurance>)`) and `declared authority`, when the task
recorded a switch; then "The applicable check ran ..." whenever the applicable check recorded a
mode. A check that recorded no mode adds nothing. Renderings share `domain/review_mode_render.py`. CLI: `finishup privacy conversations
agent-opt-in | owner-approval | local-only | ai-powered | status` (repository scope; widening needs
the trusted terminal decision). First-run answers (`cli/setup.py` `ReviewChoice`):
`agent_opt_in`, `local_only`, `ai_powered`, all on the `policy` route; the two that add review
reach `run_privacy_setup(ai_review_add_on=True)` (`privacy_setup.adds_ai_review`,
`PRIVATE_ADD_ON_WARNING`), and a repository's first grant asks the conversation question
(`_with_conversation_question(..., first_grant=True)`).

A `deterministic_only` check that follows a blocked or unavailable review carries that earlier
code forward alongside `semantic_review_not_requested`. The stop-rules make a blocked review a
coverage gap rather than a retry, so the fallback check is the expected next step; without the
carry-forward the receipt's only surviving account would read as the agent never having asked.
The drift code never carries: it is re-added fresh on the strict-ceiling path only after reading
the live applied-route record, so a `mcp remove` (which clears the record) or a strict reinstall
cannot leave a stale drift claim on a later check.

Completion-scope gaps are a separate local-check case family. When a completion claim exists and
the readable effective current plan declares zero obligations, exactly one applies:

- `completion_scope_undeclared` — the effective plan has no obligation refs and no typed
  `no_obligations_reason`;
- `completion_scope_declared_none` — the effective plan has no obligation refs and carries a typed
  reason.
- `completion_claim_outside_plan` — an effective completion claim names an obligation outside the
  readable current plan.
- `completion_plan_not_claimed` — the readable current plan names an obligation omitted by an
  effective completion claim.

Both force `coverage_incomplete`, `insufficient_coverage`, and an insufficient-coverage receipt.
The typed declaration records the participant's scope decision but never purchases a clean verdict.

Five further codes describe a review that did run but could not deliver everything it produced:

- `semantic_review_context_withheld` — the review ran without categories its own profile selected;
- `semantic_review_value_redacted` — egress privacy replaced one or more credential-like values in
  the sent packet, in place, with `[withheld-by-yoetz:possible-credential]`; the rest of each item
  was sent (issue #982). It weakens neither proof class;
- `semantic_review_item_withheld` — in-place replacement could not make an item safe to send, so
  that item alone was left out (listed in `semantic_withheld_items`). It bounds only the AI-powered
  review. Either gap comes with `semantic_redacted_values` (owner-approved PL2-1, ADR-009): at most
  64 `{item_id, source_ref?, disposition: value_replaced|item_withheld, lines}` entries sorted by
  `item_id`, with up to 32 sorted 1-based line numbers in the captured item's own text (an excerpt or one of
its `-part-NN` parts, not the source file; renderings say "of the captured item") and `source_ref` only
  when the catalogued ref is an opaque token. Never a value, offset or path. Carried, when present,
  by the check event (1.4.0), check result, `status view=operation` page and receipt document; every
  rendering adds the fixed agent line once (`SEMANTIC_REDACTED_VALUES_AGENT_LINE`);
- `semantic_review_credential_heuristic_disabled` — the owner's privacy policy had the
  low-confidence credential heuristic turned off (`credential_heuristic: disabled`, issue #982), so
  values that only look like passwords or tokens were sent as written to the external reviewer;
  high-confidence detectors still applied. Emitted when an external review succeeded or its packet
  was sent; never for a local-model review. A standing limitation
  and owner disclosure choice, never agent work; it weakens neither proof class;
- `semantic_challenges_rejected` — the reviewer returned challenges and post-validation dropped at
  least one (no cited ref had content in the sent packet — reason `ref_not_carried` —, a citation
  outside the advertised set or the frozen case, an unchanged-claim over a withheld source, or
  citations whose resolved subjects exceed one finding's 64-subject bound). A cited `fnd_` from
  `citable_refs` resolves to that finding's subjects whether it is one of this check's local
  findings or a readable recorded finding inside the frozen fence, so a re-raise that names the
  earlier finding it concerns is not dropped (issue #905). A `ref_not_carried` challenge mints no
  finding but is never silent: its summary and message are appended to the recorded
  `review_summary` under a fixed header saying they are advisory and unverified (issue #976);
- `semantic_review_refs_reduced` — a reviewer item cited refs the sent packet did not carry: a
  challenge keeps only its sent refs and stands on them, a verified row is dropped (it reads as
  support, so it may not rest on unsent material) (issue #976). It blocks absence proof of an
  AI-powered finding except under that review's own explicit, admitted `fixed` ruling on the
  finding: the gap means the reviewer cited more than it was shown, not that it saw less;
- `semantic_review_snippet_invalid` — a reviewer quote could not be proved against the exact safe
  provider-bound text of the rows it cites, including after response recovery without the
  ephemeral text index. The quote is removed from a kept challenge, a verified row is dropped, and
  the remaining review stays visible;
- `semantic_case_content_over_item_limit` — recorded text the publish-side prose bound accepted
  (`MAX_TEXT_BYTES`, 8192) exceeded what one case item carries (`MAX_REVIEW_TEXT_BYTES`, 4096), so
  the case shortened it or replaced the payload with a `yoetz.bounded-content-omission/1` marker.
  The marker's `reason` is `over_case_item_limit`, distinguishing a size drop from the
  `not_selected` omission the selection policy raises for material it declined to carry.
- `semantic_case_finding_refs_over_limit` — a local finding cites more subjects than one case
  item may link (`MAX_SEMANTIC_ITEM_SUBJECT_REFS`, 16; a finding may cite up to 64). The finding
  keeps its identity in `local_check_refs` and in the check result, but the case carries neither
  its prose nor its projected assessment: both appear as explicit `not_selected` omissions
  (`finding_summary` and `bounded_structural_metadata`) and this gap names the capacity reason.
  References are never sliced to fit; a partial subject list presented as the finding's own would
  be a different finding. The review still dispatches once with the other findings.
- `task_statement_unavailable`, `task_statement_not_supplied`, `task_statement_not_authorized` —
  what the reviewer knew of the user's request (issue #908; see "Task statement" below).

Four codes bound the ADR-031 check-time change, the service's one read of the task's repository
for a check whose recipe selects diff excerpts. They appear on the packet and check coverage only
when that recipe selected the change:

- `check_time_change_unavailable` — the check named a workspace but no part reached the packet: a
  workspace outside the task's repository, an unsupported Git state (linked worktree, unsafe root,
  a filter or include in the effective config, partial clone, a system Git older than 2.25), a failed or
  timed-out capture, a change withheld whole by redaction, or no claim, obligation or plan to link
  it to. A check whose connection named no workspace has nothing to read and reports no
  check-time code;
- `check_time_change_base_unavailable` — no resolvable task-start commit, so the change is shown
  against the commit the task's first check pinned (or HEAD when no pin could be kept), and work
  committed before it is missing;
- `check_time_change_truncated` — a changed file (named in the change's header), a part of the
  change, or untracked names beyond the listing bound did not reach the reviewer;
- `check_time_change_redacted` — credential-like spans were replaced before storage and review,
  in the change or in a task input file it carried, or such an input was withheld whole;
- `check_time_change_path_unrepresentable` — the check's local, metadata-only read of changed
  paths skipped at least one path whose name holds a carriage return or line feed (issue #1019).
  The read stays usable: each skipped path counts as omitted, the listing is marked truncated, and
  a requested file it could not list stays unproven rather than unchanged. A standing limitation,
  classed with the other check-time codes; never a finding, and the path is never recorded.

Post-validation fences each challenge independently: a rejected challenge costs only itself, the
challenges beside it still become findings, and the drop is declared through this gap. A judgment
that fails the *structural* fence yields no AI-powered findings at all and is recorded as
`invalid` / `semantic_judgment_rejected` — never as a failed request. A check always commits its
local findings, whatever the reviewer returned.

The not-configured and not-run codes share the honest compact limitation that AI-powered relevance
review was not run; they must not reuse blocked-by-policy wording. The not-requested code marks every
local-only check and forces coverage incompleteness without changing the local-check
verdict.

Ready check composition resolves the configured external provider against the live
generation-fenced registry for every AI-powered check. A provider binding activated after ready
composition can therefore serve a later check without a service restart; a binding removed after
composition cannot be used from the stale readiness snapshot. Exact credential-record presence is
checked structurally without reading the secret; minting secret material remains dispatch-time only.

An AI-powered check also appends one bounded diagnostic record when no provider endpoint is bound,
its task route is inactive, the exact configured binding is absent from the live registry, or the
outer check coordinator catches an evaluator exception. A missing exact credential record shares the
credential-unavailable path. These paths use exactly one operation token:
`semantic_not_dispatched_provider_unbound`, `semantic_not_dispatched_route_inactive`,
`semantic_not_dispatched_credential_unavailable`, or `semantic_not_dispatched_coordinator_failure`.
The reason is a closed structural token; provider identity, exception text, payload, and paths
remain forbidden from this sink. Exceptions contained inside the production composition evaluator
retain the existing `semantic_evaluation_failed` operation.

When the unresolved endpoint is a Codex subscription runtime whose local structure is not ready
(issue #855), the credential-unavailable record, and the fallback-engaged record when a paired
fallback serves instead, are preceded by one `semantic_external_runtime_unready` record with the
same `request_id`. Its reason is the closed structural state from the ADR-006 retention amendment,
for example `codex_runtime_executable_changed` or `codex_runtime_profile_outdated`. The public
`semantic_status` / `semantic_reason` pair is unchanged. The state is read from the binding,
executable bytes, and dedicated home only: no login probe, no Codex process, no credential read.

Two further check-path operations describe a review that did reach a provider:
`semantic_judgment_rejected` records a structurally unusable judgment, and
`semantic_review_accounting` is appended once per dispatched review carrying counts only —
`semantic_conclusion`, `semantic_challenges_returned`, `semantic_candidates_accepted`,
`semantic_challenges_rejected`, the per-reason split `semantic_rejected_<reason>`
(`ref_not_carried`, `ref_outside_case`, `hidden_source_claim`, `subject_refs_over_limit`,
`routine_completeness`, `yoetz_process_state`, `local_rule_owned`),
`semantic_review_refs_reduced`, `semantic_review_snippets_rejected`,
`semantic_restatements_suppressed`, `semantic_challenges_advisory` (routine correctness notes,
#1042), `semantic_agent_criteria` (#1043), `semantic_prior_rulings_set_aside`,
`semantic_rulings_disputed_after_rebuttal`, `semantic_findings_selected`,
`semantic_findings_suppressed`. A third operation, `semantic_review_follow_up`, is appended once
per in-check follow-up round (#1047) with `semantic_follow_up_round`, `semantic_follow_up_items`,
`semantic_follow_up_refs_added` (sources the round's packet showed whole for the first time) and
`semantic_follow_up_parts_added` (excerpt parts it carried that no earlier packet of the check
carried, tb4n5). Every one of these is a closed field of both the stderr sink and
the durable diagnostic ring: the counters are integers and `semantic_conclusion` is a closed token
(`observability/logging._FIELD_ORDER`, `observability/privacy._INTEGER_FIELDS` /
`_TOKEN_FIELDS`, `observability/diagnostics._FIELD_ORDER`); a name either sink does not know is
dropped there.
The counts reconcile (`returned == accepted + rejected + suppressed restatements + advisory notes`,
`accepted == selected + suppressed findings`), so
"the reviewer answered and none of it reached you" is never invisible. Challenge text, refs, and
provider identity remain forbidden from this sink like every other.

The check-applicability gap family follows the same material-state rule: `check_not_applicable`
means material work was appended after the recorded check and superseded its verdict, never that
the frontier merely advanced. A finding-free suffix made entirely of service-stamped observation
records also keeps the check attributable: observation reports what the harness saw rather than
publishing new cooperative work on the participant's behalf. An observation-authored
`finding_recorded` still invalidates the older check. An `acknowledged` or `provenance_disputed`
response to an observation-authored, non-actionable finding
(`kernel/projections.is_observation_limitation`: the service-stamped observation coordinator
authored its record, and its kind is in the explicit allowlist `OBSERVATION_LIMITATION_KINDS` and
its closed `actionable` trait is false) also keeps the check attributable: no check returns such a
disclosed limitation, no local pack scores those dispositions, and a recheck could not change the
result (#911). A kind outside the allowlist stays response work even when it is not actionable. A
rejection or waiver of that finding, which the local packs score, and every response to any other
finding the check did not return, still revokes it.
`check_current_as_of_earlier_frontier` is the qualified attribution in this family: when only
check-answering responses, such limitation acknowledgements, and/or observation records FinishUP
cannot prove harmless follow the check, its coverage still contributes while the receipt names the
subject frontier its verdict is current as of. Which later records count is one predicate,
`kernel/later_material.later_material_class(record, projection)` (re-exported by
`kernel/reducers`), with the closed classes `yoetz_own_call | response | exploration |
no_tool_activity | non_counting_write | edit_or_write | other` (ADR-040 section 7, tb4n3 RC-6,
#1029). The first four observation classes (a hook or stream observation of one of FinishUP's own
MCP tools in any host spelling, a read-only run, host stream bookkeeping that names no tool call,
a scratch or FinishUP-owned write) are ignored: no gap, no supersession. `edit_or_write`, an observed
deliverable, workspace or outside-workspace edit (an edit tool, or a command whose runtime tokens
record a counting shell write, `observed_shell_write_counts`, ADR-045), supersedes the check
exactly like cooperative material work. `other` and `response` keep the disclosure. `kernel/check_standing.check_standing`
is the one walk over the records after the latest check; the receipt context, receipt capacity,
compact status coverage and closure readiness all read it, so none can disagree. The application
classifies the counted suffix (`kernel/receipt_builder.CheckSuffixClass`: responses only,
observations only, or mixed) so the limitations sentence names what actually followed the check
instead of assuming responses; the class is render context, not a wire field or gap code (#657).
A response suffix that includes a limitation acknowledgement is named as responses "to the
findings it returned or to observation-authored coverage limitations".
`kernel/reducers.invalidates_recorded_check(record, check_sequence, returned_finding_ids, *,
limitation_finding_ids, projection)` is the single predicate deciding whether a record supersedes
the check; the reducer's projection freshness applies the same rule. Lineage and work-state events
such as `work_closed` are not material and never revoke a check.

## 9. Kernel (`kernel/`)

- `kernel/closure_readiness.py` owns the closed, versioned gap classification
  (`GAP_CLASSIFICATION`, `GAP_CLASSIFICATION_VERSION`, `GapClass`, `gap_base_code`,
  `classify_gap`, `split_gaps`), the per-request `ClosureReadinessFacts`
  (`closure_readiness_facts(projection, records)`), the checklist derivation
  `derive_closure_readiness(blocking_conditions, gap_markers, facts, *,
  semantic_review_required)`, and `ACKNOWLEDGED_NOT_DONE`. It is pure: it reads the projection and
  the recorded prefix only, and it never changes coverage, a verdict or a receipt (ADR-032).
- `ProjectionState` (frozen): `frontier`, `head_digest`, `plans`, `obligations`, `decisions`,
  `assignments`, `actions`, `results`, `evidence`, `claims`, `contradictions`, `findings`,
  `responses`, `latest_tested_state`, `freshness`, `unknown_event_count`, `coverage_gaps`.
  `latest_tested_state` is exactly the source check event ID, subject frontier, verdict,
  `returned_finding_ids`, `suppressed_count`, and recorded coverage. Suppression is durable
  structural uncertainty: it is never reconstructed from visible finding IDs.
  `freshness` folds staleness under the same supersession rule as
  `kernel/reducers.invalidates_recorded_check`: a readable `response_recorded` answering a finding
  in `latest_tested_state.returned_finding_ids` never by itself marks the ledger stale.
  `freshness` is a function of carried state alone, never of which event is being folded. Its
  precedence is unchanged — genesis, `redacted_*` markers, `unknown_event:`/`missing_ref:` markers,
  supersession — and below those it reports `latest_tested_state.coverage.ledger_freshness`, so a
  check that recorded `partial` holds the scalar at `partial` for as long as it is the retained
  check. Only supersession, a redaction removing that check, or a later check replacing it moves
  the scalar off that value. The scalar therefore cannot read cleaner than the coverage of the
  very check reported beside it (issue #307).
  `CurrentPlanScope` and `current_plan_scope`, owned by `kernel/plan_scope.py`, are the one shared
  readable-plan-chain derivation consumed by status, check, and receipt: effective obligation refs,
  their declared count, and the current `no_obligations_reason`. A revision applies its obligation
  changes and restates the reason;
  omission clears it. The derivation reads no prompt, source code, workspace state, or prose. If a
  plan-chain payload is redacted or otherwise unreadable, or an unknown plan-family event prevents
  interpreting the chain, scope remains unknown and never becomes an empty tuple or zero count. By
  contrast, an obligation ID in a readable plan remains a known declared ref when its obligation
  row is missing or redacted; it is counted, treated conservatively open, and carries the existing
  missing/redaction gap.
  `ProjectionRecord.redacted` is the generation-1 historical name for the common null-payload
  tombstone bit: it is true exactly when that record's event payload is unavailable. It is not by
  itself proof that a `redaction_recorded` event exists. An accepted-envelope state of
  `logically_redacted|erased_claimed` or an effective `ReplayIndex` target proves recorded
  redaction; `key_unavailable`, or `present` with an unreadable payload object, proves
  non-redaction unavailability. The frozen case-availability facts below bind the latter snapshot
  without changing the frozen projection/snapshot shape.
- A projection contradiction is one explicit unresolved `ClaimRecordedPayload.disputes_refs`
  edge. Its internal key is `ContradictionKey(disputing_claim_id, disputed_ref)` and its canonical
  snapshot key is exactly `"<disputing_claim_id>|<disputed_ref>"`; `|` cannot occur in either
  registered ID grammar. `ContradictionRecord` is exactly `(disputing_claim_id, disputed_ref,
  source_event_id, source_frontier)`. Re-publishing the same `claim_id` replaces all contradiction
  edges previously asserted by that claim with its new exact `disputes_refs`; a decision alone does
  not clear an edge. Orphan action/result links remain their visible record plus a coverage gap and
  policy input, not a second contradiction family.
- `effective_claim_ids`, owned by `kernel/claims.py`, removes only claims explicitly named by a
  `claim_recorded/1.1.0.supersedes_claim_refs`. The edge is durable, not payload-derived: applying
  the replacement writes `superseded_by_claim_id` onto each target's `ClaimProjectionRecord` (the
  snapshot key is emitted only when set, so pre-existing snapshots stay byte-identical), and
  `effective_claim_ids` reads that field. Redacting the correcting event therefore cannot resurrect
  its target as a current claim, and cannot free that target for a second correction. Local-check
  current-claim rules, AI-powered review claim sections, and receipt current-claim selection consume
  that set. Projection and status history retain both old and replacement records; finding
  resolution remains a later-check transition and never deletion. `disputes_refs` and
  `decision_recorded.supersedes_event_id` are not claim-supersession aliases.
- `EvidenceObjectSource` is the frozen `(evidence_id, source_event_id)` pair. `ReplayIndex` is the
  frozen non-plaintext `(frontier, head_digest, payload_event_by_object,
  evidence_sources_by_object, redaction_root_by_object)` reverse index derived solely from the
  accepted envelope/locator prefix. `empty_replay_index()` and `extend_replay_index(index, event)`
  own its exact contiguous construction. `reduce_event(state, event, replay_index) ->
  ProjectionState` is pure and requires the index through that exact event; `replay(events)` extends
  the index before each fold. An incremental adapter retains it or locally rebuilds it from accepted
  envelope/locator rows; it never opens payload objects.
- `UnavailableCapturedObject` is the frozen `(source_event_id, object_id)` identity of one current
  evidence source whose declared captured-content object cannot be verified at the case snapshot.
  `CaseAvailabilityFacts` is exactly `(unavailable_event_ids,
  unavailable_captured_objects)`: the first member is a sorted-unique tuple of current accepted
  source event IDs whose payload is null, whose envelope state is `present|key_unavailable`, and
  which have no effective redaction target; the second is a sorted-unique tuple of
  `UnavailableCapturedObject` values ordered by event-ID then object-ID bytes. These facts are
  structural availability observations only; they contain no plaintext, path, key identifier, or
  adapter exception. `LedgerPort.load_case_availability(session_id, frontier, projection)` is the one shared
  memory/SQLite snapshot operation. `freeze_case` uses that same operation internally, and
  `status(candidate_findings)` calls it explicitly. Its canonical digest is part of the check
  dependency digest, so final commit cannot silently rely on availability that changed after
  freeze.
- `DeterministicCase` is the pure kernel input `(projection, frontier, availability, allowed_ids,
  coverage_by_ref, gaps)`. `availability` is the exact `CaseAvailabilityFacts` value used to build
  the case. `coverage_by_ref` is an immutable exact ref-to-`Coverage` index derived
  from authoritative accepted envelopes and current projection source links; it is never guessed
  from a publication channel. `CaseGap` is exactly `(marker, code, subject_refs)`. A gap may have
  empty `subject_refs` only when it is genuinely task/global; such a gap weakens coverage and
  receipts but cannot fabricate a public `Finding`, whose subject refs remain nonempty.
  `redacted_object:<object_id>` has exactly one root: the causative redaction event with the lowest
  ledger ingestion sequence. Repeated redactions remain visible in the ledger but cannot replace
  that first-cause public root. Object-only payload deletion also creates the effective
  `redacted_event:<event_id>` marker; captured-content deletion marks only the matching current
  evidence source unavailable. Missing causative roots are corruption.

  Per-ref weakening preserves publication channels, authorship, and check types. Redacted or
  otherwise unavailable event payloads cap artifact observation at `published_only`, immutability
  at `metadata_only`, and freshness at `redacted_gap`, adding respectively `redacted_event` or
  `event_payload_unavailable`. Redacted or otherwise unavailable captured content uses the same
  artifact/freshness caps but caps immutability at `content_digest`, adding respectively
  `redacted_object` or `captured_object_unavailable`. An unresolved typed ref preserves all other
  dimensions, caps freshness at `partial`, and adds `missing_ref`; an opaque event does the same and
  adds `unknown_event`. Finding and contradiction citations may name an `evt_` id that is absent
  from the accepted prefix (observation advice historically computed those ids from envelopes that
  were never appended). Replay does not mint one `missing_ref` marker per such citation — that
  would overflow the 64-gap projection and receipt bounds on a large observation finding set.
  Case construction instead keeps those citations out of `allowed_ids` and, when no `missing_ref`
  is already present, adds one task-global `missing_ref:cited_event_absent` gap. Projection
  `source_event_id` values, selected frozen-history members, and
  `latest_tested_state.source_check_event_id` remain required: a missing one is still an invalid
  case and surfaces as a bounded `STORAGE_CORRUPT` receipt/status/check error, never
  `INTERNAL_ERROR`. Every cap is a registered component-wise
  minimum, existing gaps are unioned and sorted, and overflow of the 64-token bound fails case
  freezing rather than truncating.
  Relevant digest evidence additionally contributes `evidence_digest_subject_legacy_unknown`,
  `evidence_content_digest_only`, or `evidence_content_withheld`. Relevance follows the current
  claim/obligation/response support graph (including referenced results); unrelated historical
  evidence contributes no gap to the current case. The two caller-digest codes
  (`kernel/deterministic_checks.CALLER_DIGEST_PROVENANCE_GAPS`: `evidence_content_digest_only`,
  `evidence_content_withheld`) stay exact case gaps and weaken every ref they root, but they are
  never subjects of the work-integrity `ledger_stale_or_incomplete` finding (issue #912). Every
  service producer records `captured` availability, so these bindings are always
  `caller_asserted`; no response, recheck, or ordinary publication can change them. The receipt
  instead names them once as a provenance label whose count is the number of distinct per-item gap
  roots (a code carried only by check coverage is named without a count); when both codes are
  counted, the label breaks the total into digest-only items (bytes not retained) and withheld
  items (the publisher recorded the bytes as withheld) so the two retention semantics stay
  distinguishable. The service-side binding of a caller digest to a matching captured object or
  byte range is not implemented; issue #912 owns it.
  `evidence_digest_subject_legacy_unknown` still roots that finding, and the finding's
  provenance addendum names only agent-performable actions.
- `FindingBasisRef` is exactly
  `EventId|ObligationId|ClaimId|ActionId|ResultId|EvidenceId|FindingId`. `FindingFact.subject_refs`
  and `FindingBasis.supporting_refs` use that nominal union, never raw unvalidated strings.
  `FindingBasis.subject_state_relation` reuses the sole domain-owned `SubjectStateRelation` enum.
  `FrozenSourceAvailability`, owned by `kernel/deterministic_checks.py`, is exactly
  `available|not_recorded|unavailable_at_freeze|redacted_at_source`; the status projection maps the
  latter two to `unavailable` and `redacted` respectively. Each policy owns one exhaustive rule
  table that freezes the primary basis IDs, public candidate roots, observed/missing fact refs, and
  supporting-ref union. Envelope `logically_redacted|erased_claimed` and effective replay-index
  targets map to `redacted_at_source`; an explicit case-availability row maps to
  `unavailable_at_freeze`. An `act|res|evd|fnd` primary ID maps to its current projection record's
  `source_event_id`; `evt|obl|clm` maps to itself. There is no first-ref or prose-derived fallback.
- `run_deterministic_policies(case: DeterministicCase, policy: PolicyPack) ->
  DeterministicPolicyResult`.
  It is pure and never reads randomness. The result contains only ordered
  `DeterministicAssessment(candidate, basis)` pairs. `FindingBasis` is internal/encrypted and binds
  the exact rule ID, observed fact codes and refs, required-but-missing fact codes, three-valued
  subject-state relation, frozen-source availability, coverage gaps, and evidence refs. Later
  review selection/privacy creates the separate content-visibility fact; the pure basis never
  depends on a context profile or disclosure policy. The
  application allocates one `fnd_` ID per normalized candidate, persists the candidate-to-ID and
  basis map in the immutable local-result object, and reuses it after a crash.
  The kernel does not own run/skipped/failed accounting. The application creates the sole
  port-owned `CheckPolicyExecution` once per selected pack: a pack excluded before invocation is
  skipped, a completed invocation is run even when it returns no assessment, and an evaluation
  failure is failed. Scope never enters the pure kernel call.
- `rank_findings(deterministic, semantic, context: RankingContext, max_findings) -> RankedFindings`
  (the exact stable `rank_key` is registered in §8; suppressed count, verdict, and the full
  weakest-material coverage baseline are retained with the ordered selection).
- `ReceiptFindingState`, owned by `kernel/receipt_builder.py`, is exactly `(finding_id, resolved,
  acknowledged_not_done, rejection_accepted)`; at most one of the three booleans is true, and the
  last two default to false (issue #905: `acknowledged_not_done` stays blocking, `rejection_accepted`
  stops blocking on a receipt whose artifact carries the terminal sections).
  The ordered tuple contains one latest current row per issue key; `resolved` is the one shared
  proof-based answer, `kernel/finding_resolution.finding_is_resolved`, read from the projection: a
  same-issue successor replaces the old row and starts unresolved, while only a later qualifying
  check resolves the current row (registered under the finding view below). A response disposition
  never resolves it. Resolved rows stay in the document's `findings` as history; the summary
  section's `items` are exactly their ascending ids (the one section every include level carries),
  and the fixed summary/findings templates append “One earlier finding was resolved by a later
  qualifying check and remains visible as history.” (or the plural form) so a reader can tell
  resolved history from current findings and from coverage gaps. Renderers derive the current set as
  `findings` minus those ids; nothing else in the frozen `receipt-document/1.0.0` shape changes.
  `ReceiptBuildContext` is exactly `(projection, subject_frontier, availability, coverage, gaps,
  finding_states, applicable_check)`, where `availability` is the current `CaseAvailabilityFacts`,
  `coverage` is the weakest material fold, `gaps` is the exact sorted typed `CaseGap` tuple after
  check, AI-powered review, and availability accounting, and `applicable_check` is the exact
  readable `CheckRecordedPayload` that still applies to this material state or `None`. The
  application folds coverage from the frozen current case, the applicable check, and every retained
  current finding row that is not resolved. A resolved row stays in the document's `findings` as
  history (named by the summary items), but a later qualifying check proved its issue absent, so
  its coverage no longer lowers the receipt coverage (issue #912); the builder's corruption guard,
  `ReceiptDocument` validation, `receipt_weakest_coverage`, and the append-time
  `kernel/receipt_capacity` gap union all skip resolved rows the same way. Documents issued before
  this rule also folded resolved rows; they still satisfy the weaker requirement and stay readable
  as issued. When an unresolved historical finding contributes a gap absent from the recovered
  current case/check, that code remains in top-level coverage and is represented once by the
  task-global internal marker `retained_finding_coverage:<code>`; the finding's own coverage remains
  unchanged.
  A check applies when no event appended after the check's own record supersedes it under
  `kernel/reducers.invalidates_recorded_check`: the atomic check-result events — the
  `finding_recorded` records it returned and its `check_recorded` — land with it and never revoke it
  (a local-check candidate that re-derives a live recorded finding with the same kind, policy, and
  subject refs keeps that finding's ID and is cited in `returned_finding_ids` without a duplicate
  `finding_recorded` event); an immaterial advance — `receipt_recorded`, `session_opened`,
  `session_resumed` — never revokes it; a readable `response_recorded` answering a finding the check
  itself returned never revokes it; an `acknowledged` or `provenance_disputed` response to an
  observation-authored, non-actionable finding never revokes it (#911); and a finding-free suffix
  of service-stamped observation-authored records never revokes it unless it contains an observed
  edit. The observation records `later_material_class` cannot prove harmless carry the
  `check_current_as_of_earlier_frontier` gap; the rest add nothing. An observation-authored `finding_recorded`, every
  other material-family event, a response to a finding the check did not return, and a response
  whose payload is unreadable all revoke it, as does an observed deliverable, workspace or
  outside-workspace edit (`later_material_class` = `edit_or_write`, tb4n3 RC-6); observations of
  FinishUP's own calls, read-only reads, host bookkeeping and scratch or FinishUP-owned writes are
  ignored and add no gap. Frontier equality is not the rule: a check necessarily
  advances the frontier past the subject it tested. The application constructs this context; the
  builder never imports a port type or re-derives applicability.
- `build_receipt(context, receipt_id, task_id, session_id, generated_at, versions:
  ReceiptVersionSlice, redaction_profile, include) -> ReceiptDocument`. Every nondeterministic input
  is explicit; the builder reads no clock or ID source. `ReceiptDocument` contains its identity,
  generation time, subject frontier, exact nonnegative `suppressed_finding_count`, and optional
  `semantic_provenance` from the applicable latest check, but not the post-append result frontier
  (which would create a digest self-reference). When no applicable AI-powered review attempt exists,
  the receipt omits that field, preserving historical local-only receipt bytes. `ReceiptResult`
  carries both subject and post-commit result frontiers. The provenance and token counters name that
  selected AI-powered review attempt; they are not a sum across retries or recovery attempts.
- Receipt boundary tokens are closed: `ReceiptFormat` is `json|markdown|text`, `ReceiptInclude` is
  `summary|standard|full`, and `ReceiptRedactionProfile` is
  `full_local|default_local_export|redacted_share`. `include` changes only the registered section
  detail level; it never suppresses required conclusion, coverage, gap, or limitation material. The
  top-level truth-bearing tuples are selected before presentation and are independent of `include`;
  summary emits sections `(summary, limitations_and_coverage, version_and_policy_identity)`,
  standard inserts `(outstanding_work, findings_and_dispositions)`, and full additionally inserts
  `evidence_and_claim_basis` before limitations. Profiles then apply the frozen field matrix:
  `full_local` retains every allowed selected text field; `default_local_export` clears obligation
  summaries and receipt-gap details but retains finding text and response reasons; `redacted_share`
  additionally omits AI-powered finding rows and rejected/waived response rows while retaining local
  ID-only findings, acknowledged responses, structural IDs, conclusion, coverage, gaps, versions,
  and the bounded AI-powered review provenance/token-usage counters. Every omitted protected content
  leaf is counted once in the sorted `ReceiptRedaction` rows; omitted structural IDs and
  enum/relation fields are not content-redaction counts. Sections are regenerated only from retained
  structural values and fixed templates; they never copy omitted text. Therefore a profile/include
  transform that changes selected fields or sections changes the canonical document and digest; it
  is not a render-only rewrite. Conclusion, subject frontier, suppression, weakest coverage, and
  material gap codes are invariant and may only stay equal or weaken. Receipt completion-scope
  wording is selected only from the shared current-plan scope state and fixed templates: “scope was
  never declared”; “the plan declared none, reason: `<no_obligations_reason>`”; or “declared
  obligations are all resolved.” The interpolation is the bounded closed enum value, never
  caller-controlled plan summary, revision reason, or other prose.
- `PolicyPack` is the frozen data-only selector `(policy_id, policy_version)`; it contains no
  callback or dynamic rule source. Its ids are `work-integrity/0.2.0`,
  `research-evidence/0.2.0`
  (`kernel/policies/work_integrity.py`, `kernel/policies/research_evidence.py`).
  No third `semantic-review` pack exists. The local coordination runtime runs
  `coordination/0.1.0`.
- Pack versions (`finishup.protocol.policy_packs`). A pack's version names the rule table that
  produced a check execution or a local finding, and moves whenever a rule changes meaning, so
  check results produced under new rules carry a new identity. `0.2.0` of both built-in packs
  (0.3 line): research-evidence raises `task_requirement_unmet` when no effective obligation cites
  the task statement and accepts statement-sourced file items as test-edit justification;
  work-integrity reports a completion that no observed run backs as
  `claim_without_admissible_evidence`, and only observed edits or runs trigger that corroboration
  rule. New checks run, and a check request may select, only the current versions
  (`check-request` 1.1.0). Every earlier version stays decodable: `PolicyVersion`, `Finding`, and
  the active `check_recorded` 1.4.0, `check-result` 1.4.0, `status-result` 1.4.0,
  `start-result` 1.1.0, `respond-result` 1.1.0 and `publish-work-result` 1.1.0 contracts admit
  `0.1.0` beside `0.2.0`, because a recorded check or finding, a check result replayed from the
  ledger, and a result an earlier 0.3 service shaped keep the identity they were written with. A
  recorded check carries one generation: every execution it records is either `0.1.0` or current.
  The released `publish-work-result` 1.0.0 still pins `0.1.0`; control 2.9.0 carries 1.1.0.
  The versions of one pack form one lineage: the finding issue key names the pack, not its
  version, and a later check that ran the pack at the finding's version or a later one can resolve
  it, so open findings recorded before an upgrade are neither stranded nor duplicated.

## 10. Ports (`ports/`)

### Ledger, projection, and durable check orchestration

`LedgerPort` is the shared memory/SQLite contract.

`AppendCommand.artifact_object_refs` is an internal application-to-ledger port field. It carries
the exact authenticated object descriptors for artifact ids already present in the draft so the
ledger can inventory them atomically with the event; it is not part of the public append request,
accepted-event wire record, or any schema digest.

Its methods are:

- `append_batch(command: AppendCommand) -> AppendResult`;
- `load_frontier() -> Frontier` (task-ledger truth without requiring a pre-existing session;
  START resumed-event content and append CAS use this value);
- `load_events(session_id, after=0, through=None) -> AsyncIterator[LedgerRecord]` (the task-scoped
  ledger chain in `ingestion_sequence` order, bounded by `after`/`through`; `session_id` is an
  authorization/membership argument, never a row filter, so a session attached to the task reads
  the whole task chain and an unknown session reads nothing. The chain is task-global, and replay
  is genesis-anchored, so a session-filtered row set would be a mid-chain suffix and no longer
  replayable — the same membership rule that `load_projection` and `query_projection` apply);
- `load_projection(session_id, view) -> StoredProjection | None` (cache/rebuild use);
- `load_case_availability(session_id, frontier, projection) -> CaseAvailabilityFacts` (shared bounded
  event/captured-object availability snapshot for case construction; an exact live projection is
  accepted, while a historical projection must equal the genesis-prefix replay at its frontier and
  may trail the live head only across an observation-authored, finding-free suffix);
- `query_projection(query: ProjectionQuery) -> ProjectionPage` (bounded public status use);
- `freeze_case(session_id, writer_id, expected_frontier, request_id, request_digest) ->
  FrozenCase | CheckCommitResult`;
- `advance_check_phase(lease, expected_phase, next_phase, durable_object_ref?) -> OperationLease`;
- `enqueue_semantic_job(lease, case_digest, case_object_ref) -> SemanticJobRecord`;
- `claim_semantic_job(lease, job_id) -> SemanticAttemptHandle` (same-owner live lease resumes the
  active started attempt; an expired operation lease rebinds an existing `started` attempt and
  preserves its provider request id, while a queued job or a job with no active started attempt
  mints the next ordinal);
- `record_attempt_outcome(handle, outcome, result_object_ref?, terminal_code?) -> None`;
- `fail_semantic_job(lease, job_id, terminal_code) -> SemanticJobRecord` (terminally closes a
  queued job when the total deadline or retry budget expires before another physical attempt can
  be claimed; it never fabricates an attempt row);
- `select_attempt(lease, handle, selected_result_object_ref) -> SelectedAttempt`;
- `load_semantic_job(writer_id, operation_id) -> SemanticJobRecord | None`;
- `list_semantic_attempts(job_id) -> tuple[SemanticAttemptRecord, ...]` (ordinal-sorted bounded
  audit rows; no raw provider text);
- `renew_leases(lease) -> OperationLease` — pending AI-powered review jobs derive their live
  ownership bound from the authenticated `yoetz.semantic-case/2` execution expiry plus five seconds,
  with operation/job renewal committed atomically. Reclaim preserves started or response-durable
  attempt identity. Local terminal recovery after that bound does not extend provider authority;
- `reclaim_operation(writer_id, operation_id, request_digest) -> OperationLease | PendingVerdict`;
- `commit_check_if_current(frozen, findings, policy_executions, semantic_status, semantic_reason,
  semantic_provenance, request_id, *, scope=None) -> CheckCommitResult` (`scope` is the request's
  normalized `CheckScopeModel`, recorded verbatim on `check_recorded`; `None` records the whole
  case);
- `fail_check_if_current(lease, failure) -> None` (last-resort terminalization for a bounded,
  non-retryable post-admission failure; records no check event and advances no frontier; retryable
  failures are rejected and remain pending);
- `lookup_operation(writer_id, operation_id) -> OperationRecord | None`.
- `lookup_task_operation(writer_id, operation_id) -> OperationRecord | None` (the caller already
  holds one task runtime; this recovery read prefers the authenticated writer, otherwise returns a
  unique prior-writer match inside that task, and fails closed as absent on ambiguous cross-writer
  reuse).

The check orchestration methods are authority-bearing port methods, not SQLite extensions.
Once `freeze_case` returns a `FrozenCase` whose `lease` field carries the `OperationLease`, an
unexpected application/protocol-value failure is
an internal failure, never caller-side `INVALID_REQUEST`. The application calls
`fail_check_if_current` before returning `INTERNAL_ERROR`; the exact operation becomes
`complete/terminal` with a durable bounded error result, same-request replay returns that error,
and a fresh check identity remains admissible at the unchanged frontier. SQLite commits the
in-memory oracle state and durable rows atomically: a failed persistence sync restores the prior
oracle state, while a successful copy-on-write commit adopts the clone into the stable state object
so an in-flight oracle's final revalidation observes every durable concurrent append.
`awaiting_human` and retryable ownership conflicts remain pending and never use this terminalization
path.
`ports/ledger.py` owns the shared closed enums: `OperationKind` is
`start|publish_work|check|respond|receipt`; `OperationState` is `pending|complete|quarantined`;
`CheckPhase` is `reserved|local_ready|semantic_wait|ready_to_finalize|terminal`;
`AttemptOutcome` is `response_durable|failed|expired|late|selected`;
`AppendWarning` is exactly `unknown_event_schema_preserved`;
`PendingVerdictKind` is `absent|live|terminal|quarantined`; and `OperationQuarantineCode` is exactly
`operation_kind_state_contradiction`, `operation_result_digest_mismatch`,
`operation_event_range_mismatch`, `operation_resume_object_invalid`, or
`operation_lease_shape_invalid`.

The exact shared frozen records, also owned by `ports/ledger.py`, are:

- `FrozenCase(case: DeterministicCase, lease: OperationLease)`, with exactly those two fields and
  `case.frontier == lease.frontier`; terminal same-digest replay is the distinct
  `CheckCommitResult`, never a nullable/fake lease or replay side channel;
- `CheckPolicyExecution(policy_id, policy_version, outcome: run|skipped|failed,
  reason: completed|material_unavailable|not_applicable|policy_failure|scope_excluded)`, constrained
  to the frozen schema's legal outcome/reason pairs and canonical pack order;
- `CheckVersionSlice(protocol_version="0.1", engine_version, projection_version, policy_packs)`,
  where policy packs are the nonempty sorted-unique registered subset bound into the dependency
  digest;
- `CheckCommitResult(outcome: committed|replayed, task_id, session_id, writer_id, request_id,
  subject_frontier, result_frontier, verdict, findings, suppressed_count, policy_executions,
  semantic_status, semantic_reason, semantic_provenance, coverage, versions)`, the internal durable
  result mapped later to the public `CheckResultModel` tree;
- `OperationLease(writer_id, operation_id, session_id, phase: CheckPhase, owner_generation,
  lease_owner_id, lease_generation: positive int, lease_expires_at, frontier: Frontier,
  dependency_digest)`;
- `SemanticJobRecord(job_id, writer_id, operation_id, case_digest,
  case_object_ref: ObjectRef, state: queued|leased|succeeded|failed|quarantined,
  attempt_count: nonnegative int, active_attempt_id?, selected_attempt_id?, lease_owner_id?,
  lease_generation?, lease_expires_at?, selected_result_object_ref?,
  terminal_code: SemanticReason?, terminal_at?)`;
- `SemanticAttemptHandle(job_id, attempt_id, attempt_ordinal: positive int,
  provider_request_id, writer_id, operation_id, owner_generation, lease_owner_id,
  lease_generation: positive int, lease_expires_at, frontier: Frontier, dependency_digest)`;
- `SelectedAttempt(job_id, attempt_id, result_object_ref: ObjectRef, selected_at,
  frontier: Frontier, dependency_digest)`;
- `SemanticAttemptRecord(job_id, attempt_id, attempt_ordinal: positive int,
  provider_request_id, state: started|response_durable|selected|failed|expired|late,
  terminal_code: SemanticReason?, result_object_ref?)` — structural audit row for one physical
  dispatch; and
- `PendingVerdict(kind: PendingVerdictKind, operation: OperationRecord | None,
  retry_after_ms: int | None)`, where retry time is present only for `live` and is bounded by the
  remaining lease lifetime.

AI-powered review attempt budget (ADR-006): `ProviderProfileConfig.timeout_seconds` is the total
AI-powered review operation deadline; `max_retries` (0..2) is the maximum additional physical
attempts (so physical budget is `1 + max_retries`, at most three). FinishUP owns the retry loop with
SDK `max_retries=0`. Transient retries are admitted only for timeout / transport / rate-limited
classes. One further class shares the same physical budget: `invalid / response_content_invalid`
(the provider was reached and answered, but the answer was incomplete or overlong) admits at most
one repair retry per job (issue #348) — the same frozen case resubmitted as a fresh physical
attempt, with no sampling, provider, model, category, or retention widening; a repaired attempt is
closed as `expired` with that terminal code so it stays in accounting, and a second
`response_content_invalid` answer terminates honestly as `invalid / response_content_invalid` (never
`retry_budget_exhausted`) with `attempted_count=2`. The repair count is rebuilt from durable attempt
rows (`repair_retries_from_rows`), not coordinator memory, so it survives an `awaiting_human`
replay. `response_schema_invalid`, `semantic_judgment_rejected`, policy blocks, human denial, secret
detection, invalid case, stale frontier, refusal, quota exhaustion, and exhausted authority never
retry. `confirm_every_request` requires a fresh foreground decision per physical attempt, the repair
attempt included. Attempt accounting (`attempted_count`, `selected_attempt_id`, terminal reason
counts, `exhausted`) is reconstructed from durable job/attempt rows via `load_semantic_job` +
`list_semantic_attempts` — not from memory-only coordinator state. When `enqueue_semantic_job`
recovers an already-terminal job (`succeeded` / `failed` / `quarantined`), the attempt loop must not
call `claim_semantic_job`; it rebuilds the final status/reason (and selected judgment/provenance
from the durable `SEMANTIC_RESPONSE` object on success) so crash-after-select or
crash-after-final-failure remains reproducible. The operation lease starts with the existing
60-second floor. Once a `semantic-case/2` job is present, renewal reads that authenticated frozen
object and extends both the operation and its active AI-powered review job to the persisted total
execution expiry plus the fixed five-second cleanup grace. A shorter execution therefore narrows the
lease to its own expiry plus grace; a longer execution is extended once and later renewals preserve
that same bounded expiry. The caller's process deadline and provider admission/approval deadlines
remain unchanged. A valid provider result must not become `operation_pending` solely because the old
60-second floor elapsed inside the frozen AI-powered review deadline, and renewal never extends
authority past the authenticated bound.

These field sets are closed: `OperationLease` and `SemanticAttemptHandle` carry the complete
owner/lease/frontier/dependency compare-and-swap fence, while job, selected-attempt, and pending
records carry only their listed durable state. `advance_check_phase` binds the durable
local-result/case object when that transition promises recoverability. The pending operation's
`resume_object_ref` is the sole current row pointer: `CHECK_RESUME` at `reserved`, atomically
replaced by `DETERMINISTIC_RESULT` at `local_ready` and retained through later nonterminal phases;
the local-result envelope authenticates its prior full-case pointer for verified reopen. The
local-result envelope also stamps the kernel's rendered finding-text contract digest
(`DETERMINISTIC_TEXT_CONTRACT_DIGEST`); on replay, a checkpoint whose bindings verify but whose
stamp is absent or from different wording is superseded — the local-check phase recomputes from
the unchanged frozen case — never `STORAGE_CORRUPT`, so a finding-wording upgrade cannot wedge an
in-flight check on its own request id. No
memory-only phase-object map is recovery authority. Recovery of that resume pointer is
operation-scoped: a deterministic rehydration failure (decode, shape, or binding of the stored
checkpoint) quarantines that operation as `operation_resume_object_invalid`, leaves `frozen_cases`
empty for it, and stores a terminal non-retryable `STORAGE_CORRUPT` so `freeze_case` and
same-request replay return that error. Events, projection, writers, and every other operation on
the task stay readable and writable. Environmental object I/O (`OSError`) during the same
rehydration remains retryable `STORAGE_CORRUPT` without latching a bundle recovery failure. A
corrupt event chain, writer table, or object inventory row remains bundle-terminal
`STORAGE_CORRUPT`. Every successful phase
advance, renewal, or reclaim returns a replacement current lease; the prior lease is spent and the
application reconstructs `FrozenCase` with the unchanged case and replacement lease before the
next step.

`OperationRecord` uses those exact `OperationKind`, `OperationState`, `CheckPhase`,
`OperationQuarantineCode`, and locator types. Its optional bounded
`OperationResultLocator(first_ingestion_sequence: int | None,
last_ingestion_sequence: int | None, result_object_ref: ObjectRef | None,
structural_ids: tuple[str, ...])` requires both sequence fields absent or both present and ordered;
`structural_ids` is sorted unique and has at most `MAX_EVENTS_PER_BATCH + 1` members. Receipt
replay uses this locator; it never scans an unbounded ledger or rebuilds the receipt. A verified
read of that stored object that fails because the envelope is tampered, missing, under the wrong
key slot, or otherwise unverifiable is non-retryable `STORAGE_CORRUPT` with the
stored-receipt-invalid family. Environmental I/O during that same verified read (a retryable
`OSError` such as EIO on a durable, valid envelope) is retryable `STORAGE_UNSAFE` with the
receipt-object-storage-unavailable family. Neither path is unclassified `INTERNAL_ERROR`.
Classified receipt object-store faults record a resolvable `correlation_id` at the application
site with a bounded exception-class reason and optional `finishup` origin; the daemon reuses that
id on the `ok:false` envelope and does not mint an `internal_error` diagnostic. Pre-append object
`stage`/`finalize` I/O on a fresh receipt is retryable `STORAGE_UNSAFE` because nothing has
committed. `execute_receipt` retains both stage handles until the complete prepared append exists.
Any failure or cancellation while the prepared append is still being built abandons both exact
stages in reverse order, including a file renamed before a failing directory fsync, so a
second-object failure cannot accumulate one finalized receipt per retry. Cancellation the commit
boundary itself refuses ahead of submission — `PreSubmissionCancelled`, raised only where the port
coroutine has not been created or has been closed unstarted — abandons them on the same terms.
Every other outcome of the submitted append, cancellation included, leaves both objects alone
because the commit outcome may be ambiguous; abandonment is never inferred from an uncertified
cancellation. The cleanup runs in a shielded task to a definite outcome before cancellation
propagates. Cleanup failure never hides the original public error, and the exact unreferenced
object remains eligible for delayed generation-fenced orphan GC.
The same retained-stage and commit-boundary rules apply to every multi-object object-first append:
cooperative `publish_work` batches and observation envelope, inspection, approved-check, and advice
materialization abandon all exact stages when object preparation fails or the commit boundary
certifies pre-submission cancellation. The guard spans the whole preparation — every draft, entry,
and command construction between the first stage and the prepared mutation — not only the
`stage`/`finalize` calls, so a rejected stored value cannot strand an already finalized object
either. Once submission begins, those callers leave the objects alone because the commit outcome
may be ambiguous.
Receipt replay binding mismatches use the same application-site correlation contract with one of
the closed structural reasons `receipt_digest_mismatch`, `receipt_id_mismatch`,
`receipt_frontier_mismatch`, `receipt_conclusion_mismatch`, or
`receipt_redaction_profile_mismatch`; the public message remains fixed and carries no mismatch
detail.

`freeze_case` uses one closed ordering for both adapters. For an absent operation: (1) a bounded
prepare snapshot establishes absent idempotency, no pending import, `expected_frontier`, head `F`,
active projection identity, and exact dependency revisions; a caller frontier may trail `F` only
across an ADR-022 observation-authored suffix, in which case the case freezes at `F` and a transient
60-second in-memory acquisition reservation immediately defers observation appends; (2) outside
every write transaction,
the adapter snapshots `CaseAvailabilityFacts`, includes its canonical digest in `D`, pages the
immutable accepted prefix through `F`, and builds the exact `DeterministicCase` from that same
availability value; (3) only after the case exists, it canonicalizes, encrypts, and durably
publishes the bound resume object; and (4) one short final reservation atomically repeats
idempotency/no-import checks,
revalidates head/projection/dependency/owner authority, and inserts `pending/reserved` referencing
that already-durable object. Case/reducer work, hashing, encryption, filesystem I/O, and object
opening are forbidden in the final write transaction. Failed revalidation writes no operation and
leaves only an unreferenced orphan-GC candidate. An expired/stale pending row instead is reclaimed
by CAS and resumes from its stored authenticated object; rebuilding or republishing a case under
that existing row is forbidden.

Pending-import exclusion is part of this ledger contract, not an importer-status read: for a new
check, `freeze_case` requires no pending import in its final reservation; for a resumed check it
requires the same predicate in the reclaim CAS. `commit_check_if_current` repeats it in its final
commit, and `append_batch` does the same for a new
`operation_kind=receipt`. Terminal same-digest replay precedes this predicate because it commits
nothing. SQLite uses the co-located importer rows; memory uses one shared task-state lock.

`append_batch` normally requires an exact task-global `expected_frontier`. A held frontier may be
behind the head only when every intervening record is observation-authored under ADR-022's exact
actor-id, actor-type, assurance, and channel predicate. The accepted batch still appends at and
reports the real head. For `operation_kind=receipt`, that suffix must additionally contain no
`finding_recorded` event, so the pinned receipt cannot append past a finding it did not cover. Any
other intervening record conflicts. Observation appends receive retryable `OPERATION_PENDING` while
a check-acquisition reservation or an *active* frozen case for their session is present. A frozen
case is active only while its pending check holds a live lease under the current owner generation.
A pending check whose `suspension_kind` is `repository_grant`, whose lease has expired, or whose
lease belongs to an earlier service generation is not an active barrier: nothing renews it and it
may never be replayed, so observation continues and the same request re-installs the barrier when
its replay reclaims the operation (issues #445, #838). Before #838 an abandoned check kept deferring
the structural delivery of its task's native capture handoffs indefinitely, and every new check on
the task waited on those handoffs. Check commit keeps the frozen subject frontier and tolerates an observation-authored
suffix after that frontier the same way acquisition and `append_batch` do; cooperative or importer
motion still conflicts. The verdict is never retargeted to a frontier the case did not inspect.

`ProjectionView` is `compact`, `assignment`, `obligations`, `findings`, `candidate_findings`,
`evidence`, `results`, `history`, or `versions`. Application status also admits `view=operation` (operation
recovery keyed by `filter.operation_request_id`); that view is not a projection row query — the
operation record is authoritative, and compact projection is only secondary enrichment for
coverage/closure and must not fail recovery on projection lag or rebuild. The port-owned
row-query view excludes `candidate_findings` and `operation` and is exactly
`compact|assignment|obligations|findings|evidence|results|history|versions`.
`ProjectionQuery(session_id, view, filter, requested_frontier, limit, position,
expected_projection_version)` uses the exact typed filter and repository-position variants frozen
in `ports/ledger.md`; `limit` is `1..100`, the expected version is absent on a first page, and
filter/position must match the view. `ProjectionPage(view, items, requested_frontier,
head_frontier, effective_frontier, lag, projection_version, rebuild_state, coverage, gaps,
next_position)` contains at most the requested count of pre-client-projection typed rows. It never
contains opaque cursor bytes, a request envelope, import status, closure readiness, result
frontier, or privacy
projection. The application alone authenticates/decodes a versioned opaque `ProjectionCursor`
into a typed position and encodes `next_position` back. Adapters filter and page at the
storage/projection boundary; application code MUST NOT materialize an unbounded `ProjectionState`
merely to answer an ordinary row-query status view.

The eight queryable raw-item mappings are closed. Assignment returns exact actor/obligation IDs,
uses the same obligation tuple as v0.1 `scope_refs`, and resolves only by a later handoff chain or
when every referenced obligation is effectively resolved. Obligation effective status is accepted
`resolved` or plan-change `superseded|waived`; `carried` preserves accepted status. Its assigned
actors come from non-handoff-superseded assignment branches, and revision is the latest same-ID
republication/plan-change event. Finding-owned fields are exact; disposition is the latest response
or `none`, and recorded waiver expiry is never evaluated against wall clock for ordering,
filtering, or resolution. The obligations row also returns `requested_items` and the exact
`unattempted_items` subset; each value remains `obligation_text` and can be projected as an
omission under a stricter client policy, while item kinds and attempt matching remain structural.
Results returns only `result_id`, source event id, payload availability, outcome, linked action id,
and evidence ids; it never returns result prose, command text, exit output, or subject-state content.
Its optional filter (issue #1084) selects by the source event's accepted envelope only:
`after_sequence` (ingestion sequence strictly after), `actor_id` (the asserted author), and
`author: "mine"` (the same self-authorship rule as evidence). A status request's `limit` defaults to
`"20"` when omitted, and `detail` selects `full` (the protocol default) or `brief`. A brief body
(`status-result` 1.4.0 `brief_success`) is a strict subset of the full one: frontiers equal to
`result_frontier`, projection metadata at their current defaults, an empty import status and an
enforced credential filter are omitted; the compact view keeps `coverage` and `closure_readiness`
and every other view carries `closure_state` (state, blocking conditions, agent-actionable tokens).
It is built before the disclosure boundary, so the privacy projection and its commitment cover
exactly the brief body. The MCP `status` tool asks for `brief` unless the agent names a `detail`;
the CLI, hooks and the bridge's own recovery reads keep the full body. A publish operation page
adds `server_filled` when the operation recorded one. The MCP text summary of a brief non-compact
body renders `Closure: <state>.`, the `Agent-actionable:` tokens and the count-free directive (for
`ready_with_limitations`, "Nothing further to do. Request the receipt.") from `closure_state`, and
omits the counts a brief body does not carry instead of printing them as unavailable.
Together with history's claim event/schema identity and candidate findings' bounded claim/result
ids, this is the minimum public projection needed to author and dry-run a v1.1 replacement without
reading raw ledger internals.
Evidence strength is exact, availability concerns only declared captured
content (never a path/URL probe), and freshness is the weaker source-envelope/projection freshness
capped at `redacted_gap` for unavailable captured content. History is accepted-envelope metadata
including caller-asserted `occurred_at`, digest-bound service `accepted_at`, and the exact
`occurred_at_consistency` comparison. The comparison is `within_forward_skew_allowance` through
five seconds ahead of acceptance and `ahead_of_forward_skew_allowance` beyond it; it verifies no
outside clock. Ordering remains ingestion sequence and caller time is never a sort or filter key.
New check cases carry both clocks and this classification in their bounded frozen timelines;
versions is one verified runtime manifest; compact uses exact structural counters and bounded
summaries. The versions slice reuses `version.py` (`build_status_version_slice_facts`): live
Python/APSW/SQLite/source-id values are the same probes as `version --json`, and a missing or
unrepresentable probe serializes as the token `unavailable` rather than a historical constant.
Protocol, engine, projection (`yoetz/0.1.0`), object format, policy-pack ids, and
`storage_schema` (`1`, the slice's static storage identity — not catalog/bundle counters and not
SQLite `user_version`) are package contract facts. `provider_profiles` is the packaged
`support/runtime-support.json` inventory, not a live AI-powered evaluator census; an empty catalog
in `development_unverified` support does not prove an evaluator is absent. MCP and CLI
`status view=versions` share this producer; `route_profile` remains an application overlay of the
serving process. Kernel evaluation does not read this live environment. Historical check/receipt
engine identities stay the recorded event values and are not rewritten by this diagnostic.
The compact singleton's `freshness` follows the same weaker-of-two rule as the evidence
view: it is the weaker of the projection scalar and the `ledger_freshness` of the applicable-check
coverage reported in the same item, so the summary line an agent reads can never claim the ledger
is cleaner than the coverage vector beside it. `StatusCompactItemModel` rejects the inverse
(issue #307).

Finding response does not resolve. The issue key is `(origin, policy_id, kind, complete canonical
subject_refs)`; it omits `policy_version`, so a row a newer version of the same pack re-raises is
the same issue. A later same-key row supersedes the old and starts unresolved.
Resolution is proof-based and replay-derived, owned by `kernel/finding_resolution.py`: the reducer
folds every readable `check_recorded` event into each finding's projection record as
`resolved_by_check_event_id` (`FindingProjectionRecord`; the snapshot key is emitted only when set,
so pre-existing snapshots stay byte-identical). The same record carries
`reduced_scope_raising_check_event_id`, emitted only when set, when the check whose completed
AI-powered review raised the row (same tested frontier and review attempt) recorded
`semantic_reference_scope_reduced` (#904); redacting that check clears it. When a resolution
qualified only through that recorded scope, `resolution_raising_check_event_id` (also emitted only
when set) names the same check, and redacting it reopens the row like redacting the proving check.
A check resolves a current row only when all of these hold: its recorded `subject_frontier` is at or
after the finding's ingestion sequence; every finding it returned is readable and none shares the
row's issue key; `suppressed_count` is zero; an execution of the row's `policy_id` at the row's
`policy_version` or a later version of that pack is `run/completed`; its normalized `scope` is whole-case or names one of the row's
`subject_refs`; its coverage `ledger_freshness` is not `stale_after_material_change|unknown`; and
its `known_gaps` lie within the proof class's closed tolerated set. `redacted_gap` also blocks by
default. One local-only exception admits it when the finding's own recorded coverage was readable
and the check-wide gap set contains only tolerated codes including at least one host-observation
code; this keeps unrelated host capture limits from making a structured-ledger repair permanently
unprovable. For local rows the tolerated set is the AI-powered review absence/weakness codes
(`semantic_review_not_requested|semantic_review_not_configured|
semantic_relevance_review_not_run|optional_semantic_review_blocked_by_policy|
optional_semantic_review_registration_drift|
semantic_review_context_withheld|semantic_review_item_withheld|semantic_review_value_redacted|
semantic_review_credential_heuristic_disabled|semantic_challenges_rejected|semantic_review_snippet_invalid|
semantic_review_refs_reduced|
semantic_missing_agent_suppliable|semantic_missing_structurally_unavailable|
semantic_missing_already_supplied|semantic_missing_items_rejected|
semantic_case_content_over_item_limit|semantic_case_finding_refs_over_limit|
semantic_prior_findings_over_limit|semantic_prior_verdicts_unsupported|
semantic_restatements_suppressed|semantic_process_state_filtered|
semantic_review_deferred_before_first_edit|check_time_change_unavailable|
check_time_change_base_unavailable|check_time_change_truncated|
check_time_change_redacted|check_time_change_path_unrepresentable`) plus the evidence-strength
codes
(`evidence_content_digest_only|evidence_content_withheld|evidence_digest_subject_legacy_unknown`)
and the host-observation codes (`captured_object_unavailable|capture_handoff_retired|
content_unselected|host_outcome_unavailable|unpaired_event`), plus the review-selection code
`semantic_reference_scope_reduced` (#904): the local-check case is not reduced, so a bounded
AI-powered review packet is not a limitation of local proof. Those host and selection codes remain
receipt coverage limitations; the host codes only stop vetoing local absence proof because local
packs judge structured event payloads and typed coverage, never captured-object bytes. If missing
content matters to the rule, the completed pack re-fires the issue or returns its own coverage
finding. The exception also requires the finding's original coverage to contain only the
pre-existing AI-powered review, evidence, host-observation, and selection tolerances and to have
freshness outside `stale_after_material_change|redacted_gap|unknown`. For `semantic_model_derived`
rows only the evidence-strength codes, `semantic_prior_findings_over_limit`,
`semantic_prior_verdicts_unsupported`, `semantic_restatements_suppressed` and
`semantic_process_state_filtered` are tolerated outright
(plus, for a row the check records a `fixed` ruling for, the insufficient-packet codes,
`content_unselected` and the environment task facts, #1000 and #1046), and the check must also record `succeeded/semantic_completed`; the
capture-baseline comparison below (#884, #904) may also tolerate codes already in the row's own
recorded baseline. Two closed families are decided by meaning rather than by baseline. The
advisory plan-drift codes (`plan_unrefined_before_first_edit|
obligation_evidence_stale_after_scope_edit|instruction_requirement_unmapped`) are tolerated for
local rows only: they describe the planning trace, not ledger rows a local pack failed to read.
The structural test-edit accounting codes (`preexisting_test_baseline_unknown|
preexisting_test_modified|preexisting_test_renamed|preexisting_test_deleted|
preexisting_test_skipped|preexisting_test_skip_unknown`) are decided by the finding's basis, not
its kind (ADR-032 pilot-blocker amendment). Only the local test-edit finding (a
`task_requirement_unmet` row whose summary is not a task-statement wording; an unknown summary
reads as this stricter basis) is bounded by `preexisting_test_baseline_unknown`; it tolerates the
informational codes and `preexisting_test_skip_unknown`. Every other row tolerates the whole set,
including the statement-based `task_requirement_unmet` rows (summary in
`TASK_STATEMENT_FINDING_SUMMARIES`) and AI-powered rows of any kind. A statement-based row is
blocked by `instruction_requirement_unmapped` on the later check, the material that contradicts
its repair; once that code is gone it also tolerates `completion_scope_undeclared`. Every row,
local or AI-powered, tolerates `completion_scope_declared_none`, the agent's own recorded scope
decision (a no-material-work task must still be able to clear a repaired finding). The actionable `preexisting_test_edit_unjustified` blocks every row. All of these codes
stay on check, status and receipt coverage. The command-attempt codes
(`command_attempt_uncorroborated|command_attempt_mismatch`) are tolerated by local rows of a kind
whose rule never reads command attempts or command identity (`completion_with_open_obligations`,
`claim_without_admissible_evidence`, `result_without_action`, `stale_evidence_for_changed_state`,
`contradictory_claims_unresolved`, `weak_or_stale_response`, `task_requirement_unmet`), by a
`requested_item_never_attempted` row whose obligations, read from the pre-check projection, request
no command, and by an AI-powered row whose subjects, read from the pre-check projection, name no command obligation,
command action or command result. `obligation_evidence_stale_after_scope_edit` is tolerated by an
AI-powered row whose subjects name none of the stale resolved obligations
(`kernel/plan_drift.stale_resolved_obligations`). Outside these and the narrow command-gap
partition described below, any other gap — redacted or unavailable payloads, redacted objects,
missing refs, unknown events, any other completion-scope code, import range, or a code not in the
list — blocks both proof classes. A local-only check therefore never resolves an AI-powered finding, and a
weakened AI-powered review never resolves one either. A check that returns a finding again clears
that row's proof; a resolved row is excluded from finding-ID reuse (`prior_finding_ids`), so a
re-fired issue is a successor under a fresh id that starts unresolved while the resolved row keeps
its proof; redacting the proving check clears the proof and the `redacted_event` marker names why.
Weak, skipped, failed, capped, stale, and non-overlapping checks do nothing and never reopen
resolution while its proof remains visible. `finding_is_resolved(state, finding_id)` is the one read
every surface uses (receipt finding states, `receipt_blocking_finding_count`, the status finding
row's `resolved`): proof present, and the latest response, if any, readable and not
`provenance_disputed`. The released `status-result` 1.1.0 finding item pins `provenance_disputed`
rows to `resolved=false`; the rule honours that pin, so such a row stays receipt-blocking until a
versioned status result lifts it. Therefore `CheckRecordedPayload` carries required normalized
`scope` (both tuples empty means whole case; the ledger records the request's normalized scope,
never a synthetic whole-case value) and required exact `policy_executions`;
policies/frontier/returned IDs alone cannot prove applicability.

`include_resolved` absent/false adds `resolved=false`, while true removes only that predicate;
`include_unavailable` has the identical rule for `available=true`. Filters are otherwise ANDed.
The evidence filter's optional `author` accepts only `mine`: it keeps rows whose
source event the requesting writer published in its current session at or before the page frontier
through `cooperative_mcp` or `local_cli`, decided per request from ledger authorship by the same
rule as `self_authored` provenance; hook-observed, other-writer, engine and import rows never
match. Attach opens a new session with a new writer, so it matches none of the rows published
before it. Every evidence row carries the ledger-recorded `publication_channel` of its source event:
a cooperative writer can record only `cooperative_mcp` or `local_cli`, while import and
observation channels are service-only. Both fields were added in place to
the unreleased 0.3 status request 1.2.0 and status result 1.4.0 (carried by control 2.9.0); the
row field is optional on the wire so results from earlier 0.3 builds still validate, although the
service always fills it. Omitting `author` keeps the earlier filter digest, so an earlier cursor
still binds.
Assignment/obligation/evidence IDs sort ascending; findings use the complete mixed-direction
ten-part rank order; history uses ingestion sequence. The repository selects at most `limit + 1`
indexed structural candidates and hydrates only the first `limit`; an unreadable selected row is
omitted without backfill while its cursor position advances, and lookahead is never decrypted.

Adapters maintain a finite replay-derived nonplaintext query index: frontier validity intervals;
compact title/plan locators, counters, coverage, and gaps; assignment/obligation actor/ref/status/
revision edges; complete finding issue/rank/response/check-scope/policy-execution/returned-ID facts;
evidence strength/freshness/object/state-digest facts; and accepted-history metadata. Required
indexes cover every closed filter plus the declared order and both directions of ID edges. No
title, description, scope prose, finding prose/reason, evidence reference/description, provider
text, payload JSON, or arbitrary metadata is stored in those columns.

Redaction globally scrubs payload-derived query columns/edges and leaves only minimal tombstone
identity, including for older frontier intervals. Tombstoned assignment/obligation/finding/
evidence rows are omitted with `redacted_event`; non-redacted selected rows whose event/response
payload cannot open are omitted with `event_payload_unavailable` when the item requires hydration.
Non-redacted assignment and all history/version items remain structurally renderable.
`include_unavailable` applies only to captured evidence objects. Compact still counts every
obligation tombstone as open and every finding tombstone as unresolved, omits unreadable bounded
summaries without backfill, and omits the singleton if task title is unreadable. History/versions
remain structural. Page coverage is `coverage.weakest` over every accepted envelope through the
effective frontier plus all projection/object/read caps, independent of filter/page; gaps are its
exact sorted unique known-gap tokens.

`candidate_findings` is the one registered exception to that last rule, because a local-check
rule evaluates one whole frozen case and no repository can page a rule evaluation. It loads
`ProjectionState` plus the authoritative accepted-record prefix through that frontier, calls
`load_case_availability` and the same `build_deterministic_case` used by check freeze, runs only the
local packs, and pages
the resulting tuple in pure application code. It never constructs a `ProjectionQuery`. The
exception covers rule evaluation only; ordinary row filtering stays at the storage boundary. Its
rows are `CandidateFinding` values ordered by the registered finding rank facts, with final ties
broken by canonical policy/rule/complete-subject emission order because candidates have no
`finding_id`. The durable `findings` view instead uses canonical `finding_id` bytes for its final
tie. Candidate parity covers only local findings; a recorded check may independently add
validated AI-powered findings. The view returns no `CheckVerdict` and allocates no ID: only a
recorded `check` produces either, so nothing the view returns can be responded to, waived, or cited
in a receipt (`application/status.md`, `application/check.md`).

### Start catalog

`StartCatalogPort` methods are `reserve_or_resume(StartCommand) -> StartAllocation`,
`commit_identity(StartIdentityInput) -> StartIdentityCommitments`,
`resolve_route(session_id) -> TaskRoute | None`,
`session_binding(session_id) -> SessionBinding | None` (active binding for either an active or
historical session of the same task),
`list_workspace_task_ids(workspace_ref_commitment) -> tuple[str, ...]` (task ids only, ascending,
non-quarantined; no public MCP surface yet),
`advance_phase(allocation, phase, result: EncryptedResultRef | None = None) -> StartAllocation`,
`yield_lease(allocation) -> None`,
`complete(allocation,
EncryptedResultRef, StartCompletionEvidence)`, and `quarantine(allocation, SafeReason)`. `StartPhase` is
`route_reserved`, `bundle_ready`, `lifecycle_committed`, `result_published`, `terminal`. IDs and
route are allocated once at reservation and reused on resume. The result argument is forbidden on
earlier transitions and required for `result_published`, whose CAS pins the response object ID,
encrypted-envelope digest, canonical unprojected structural bytes, and result digest for exact
crash resume before terminal catalog completion.

Shared route values are `TaskRoute` and `TaskRouteState` (`initializing`, `active`,
`quarantined`), plus `SessionBinding(task_id, session_id, writer_id)` for typed repair selectors.
`TaskRoute` carries task ID, active session ID, generated bundle route, positive
route generation, state, the optional installation-keyed `repository_privacy_commitment`, and the
stored active route-identity digest. The repository commitment is supplied only by the trusted
control-session binding and is never derived from the start request. That digest is SHA-256 over
canonical task ID/bundle route/route generation; session/state transitions do not change it.
`StartAllocation` freezes the same generation/digest selected at reservation.
Its lease is the distinct `StartOperationLease(owner_generation: positive int, lease_owner_id,
lease_generation: positive int, lease_expires_at)` and is absent only for terminal replay; it is
not the check-specific `ports.ledger.OperationLease`. The lease's `owner_generation` is the
**start-lease / catalog generation** (the active service generation seeded into catalog meta), not
the per-bundle monotonic fence generation in `bundle_meta`.
`StartCompletionEvidence.owner_generation` carries the same start-lease generation so
`complete` can CAS against the catalog row; bundle-fence rotation is verified separately via
`validate_fence` against the fence's own `owner_generation` and nonce.
When a `result_published` allocation resumes, a deterministic verification or binding mismatch
quarantines the allocation as `STORAGE_CORRUPT`; environmental object I/O remains pending and is
returned as retryable `STORAGE_UNSAFE` so the same request can retry without losing the pinned
result.

An ordinary start that returns `BUNDLE_BUSY` after reservation attempts the shielded
`CatalogLeaseYield` transition. `yield_lease` compares the pending row's exact owner generation,
lease owner, lease generation, and unexpired expiry inside the catalog transaction, then sets
only the expiry and update time to the current clock. It preserves the request digest, all
allocated identities, phase, lifecycle event and pinned result. An exact replay reclaims that
same allocation with a higher lease generation; a changed body still conflicts. Completed,
quarantined, expired, and superseded leases cannot be yielded. Cancellation and ambiguous failures
do not take this path, because they do not establish a stopped attempt. If yielding itself fails,
the original busy error remains and no immediate-replay guarantee is made.

`LocalBundleRuntime.provision_start` waits at most five seconds for a same-bundle, same-authority
session rebind to drain active usages and pending fence validations. This is below the 60-second
start lease. The condition releases the cache lock while waiting, bounds waiter admission by
`max_pending_leases_per_task`, rejects new ordinary acquisitions of the old session while a start
waits, and keeps waited entries out of idle eviction. Release, failed pending validation and
shutdown wake the waiters; cancellation removes only the affected waiter. On wake, ordinary
service readiness, route identity and ownership-fence checks still apply. Other route/authority
conflicts retain their existing immediate refusal. `runtime_rebind_busy` identifies exhaustion of
this wait or an ordinary acquisition held back by it; `catalog_busy` identifies an actual SQLite
transaction lock and `catalog_maintenance_busy` identifies exclusive maintenance admission.
After successful yield the reason becomes `start_runtime_rebind_retry_ready`,
`start_catalog_retry_ready`, or conservatively `start_busy_retry_ready` for another producer.
`start_lease_pending` identifies an exact replay while the same-generation lease is still live.
These closed tokens support public recovery without publishing paths or caller content. They
identify reproduced producers; they do not establish which producer caused historical native
failures recorded in issue #744.

`StartIdentityInput(task_title, workspace_ref?, external_ref?)` is a redacted one-shot value;
`StartIdentityCommitments(title_commitment, workspace_ref_commitment?,
external_ref_commitment?)` contains only domain-separated installation-keyed HMAC commitments.
The application builds the start `request_digest` from those commitments plus nonsecret logical
fields. `reserve_or_resume` recomputes/verifies them before idempotency or route lookup, preventing
low-entropy plaintext from leaking through an unkeyed structural request digest. `workspace_ref`
is the caller-declared workspace or working-tree identity and `external_ref` the stable task identity within that workspace;
together they are the attach selector when `session_id` is absent (`mode=create_or_attach` or
`attach` with the pair). The `workspace_ref_commitment` is a keyed HMAC of the exact caller
string. Hook auto-attach on every host commits the canonical absolute repository root (a linked
worktree is its own root), and guidance uses the same root rather than a remote URL. The
SessionStart context names the mapped `session_id` and `writer_id`; an agent continues that task
with the held session selector. With no selector or stored binding, a new pair creates new work,
even beside a dormant task. An identical pair attaches and rotates to a fresh session and writer.
Concurrent requests for one new pair converge on one task; without a host-recovery selector,
different pairs admit separate tasks.
An initializing route reserves its exact pair while recovery remains possible.

Historical sessions remain valid `mode=attach` selectors, while ordinary routing accepts only the
active session and returns the typed current binding for a retired session. Disagreeing selectors
produce `selector_conflict`; membership never resolves that disagreement. The observation hook
checks its private persisted predecessor bindings before admitting a new task. It resumes only a
unique task selected by eligible, durably ended same-host mappings, held stable under the shared
workspace and lifecycle locks. A lost lock or ambiguous binding is a typed retry/refusal, not
permission to create a replacement task. An ambiguous refusal reports only the number of candidate
tasks beside its closed reason; it never includes their task, session, or host-binding identities.
No stored selector means new work. Successful recovery
rewrites eligible predecessor mappings and preserves their pending rows for delivery on the
successor route. Age alone does not establish a host session's end.

Host-session mapping writes are durable lifecycle operations. A cancelled or interrupted start
may leave a validated `.pending` or claimed `.applying` operation; the next lock owner replays a
bounded sequence of residual operations after queueing its latest mapping store or clear intent. The
pending file is the durable last-write queue: an owner operation coalesces an older pending loser
before apply, while a later producer remains the later operation. While that fence cannot be
completed, SessionStart and hook delivery defer service access and retain the operation for a later
retry. Claude and Cursor SessionStart wrappers preserve the reviewed closed lifecycle meaning
through their structural action, including `clear` and `compact`; unknown source values are
discarded.

**Post-compaction recap (ADR-044, issue #1027).** A host's post-compaction start (`SessionStart`
source `compact`) appends one bounded block to the held-ids cue: a receipt-style recap of what
`status` returned for the mapped session just now. Codex runs its `hooks session-start` re-ground hook and the shared observe pass concurrently on a
compact start, and the one holding the session lifecycle lock reads status and carries the recap
(compact view, then up to three bounded `obligations` pages for the declared deliverables); Claude
Code and Cursor carry it from the shared observe pass; `startup`, `resume`, `clear` and every
other event are unchanged. The recap is at most 2,400 ASCII characters inside a 4,000-character
context (`RECAP_LIMIT`, `RECAP_CONTEXT_LIMIT`; every other hook context keeps its 2,000-character
bound) and states: the held task, session and writer ids, the head frontier, the plan counts, the
readiness `state` and `agent_actionable` tokens, up to ten open obligations and ten unanswered
findings (id plus a quoted 80-character excerpt, the rest counted), the latest check's verdict, the
frontier it examined and its event id, the declared `file`/`directory` outputs with their obligations'
status (only obligations of the current plan, quoted on one line, labelled with the obligations
read's own frontier), one plain-words next-action sentence for the readiness `state`, and a count of
undelivered local rows sampled before the status read. Every line ends `[source ...]` naming the status view and frontier, the check event, the
hook mapping or the local outbox. Text `status` withheld stays withheld; a field the result did not
carry reads "not reported"; a section the budget cannot hold is named in an "Omitted for space" line.
The recap is a trigger-hook output (§ harness integration port, decision 8): it records nothing,
earns no coverage and is not evidence. Any failure leaves the held-ids cue unchanged.

Raw refs never enter structural durable state; only their commitments do. The caller-controlled
`workspace_ref_commitment` is an attachment selector, not a repository-privacy commitment, and
cannot select or inherit disclosure authority.

### Task lineage and project scope (ADR-027)

Project admission distinguishes `coordination_consent_required` (missing source-workspace
observation consent) from `coordination_source_policy_denied` (source disclosure policy refusal or
unavailable policy evaluation). Both refuse disclosure; the latter never recommends obtaining
workspace consent as sufficient authority. The additive control 2.7 error vocabulary preserves
this distinction, while older control schemas remain frozen.

The 0.3 implementation adds the wire, catalog, runtime, host-correlation, and presentation
contracts below. `AuthorizationScopeKind` and structural `contains()` retain their existing four
kinds; lineage and project membership are separate authority facts and never add an egress scope.
The storage ownership boundaries are recorded in [storage-ownership.md](storage-ownership.md).

**Project identifier.** Accepted `IdKind.project` uses prefix `prj_` (see Identifiers). A project
is host-agnostic and is a grouping object, not an egress scope. Its initial kinds are `repository`
(implicit) and `general` (explicit, amendable); membership kinds are `repository`, `workspace`,
and `task`. Membership rows carry append-only generations. Repository or workspace commitments
are membership facts and never the project's identity.

**Lineage names and facts.** A child is a real task (`tsk_`) with its own bundle. The catalog holds
`parent_task_id`, `depth`, `lineage_digest`, `origin`, `acceptance`, and `work_state`; nesting is
recorded to any supported depth within #499's configured depth and fan-out ceilings (with typed
refusals), while presentation remains one level and session health remains per session.
Work lifecycle is `open | closed | cancelled | abandoned | written_off`; session health is
`active | contact_lost | ended`; receipt history is service-owned by receipt finalization and
records the latest receipt and its frontier. The task's explicit work publication owns `closed`, a
parent action on accepted work owns `cancelled` and
`written_off`, and the recorded service abandonment policy owns `abandoned`; a receipt request
never closes work. The service records `active` for a held lease, `contact_lost` when it expires
without a host end event, and `ended` only for a host end event or explicit end. A missing host end
event never establishes permanent liveness. A live task is work `open` with at least one active
session.

Successful routed activity renews session health and clears any previous contact-loss deadline;
it does not reopen terminal work. After lease loss, work remains open for
`lineage.contact_lost_recovery_seconds` (default 300 seconds). The policy applies to root and child
tasks alike. Expiry appends one authenticated, service-stamped `work_abandoned` event to that task's
own ledger before updating the catalog. Recovery
replays that event idempotently after interruption. A parent-minted child whose handle expires
without any attach is abandoned with reason `attach_handle_expired`; its session health stays
`ended`, since no attached session lost contact. Cancellation and write-off preserve the accepted
edge. Evidence arriving after abandonment stays in the ledger and retains the incomplete outcome.
An already consumed handle can replay its original start operation after the handle expiry;
another request cannot reuse it, and revocation still fences replay. The same exact-request rule
covers the crash window between a committed child start and handle consumption: after expiry,
only the request whose start operation the catalog already recorded as complete for that child
may finish consuming the still-unconsumed handle. Every other request is refused as expired
before any callback can rotate the child route.

Admitted native hook activity is contact evidence at its own receipt timestamp, not at the time a
hook drain, the sweeper, or a retry delivers it (#837). One piece of evidence holds its current
task session active until that receipt time plus the 60-second session lease
(`SESSION_LEASE_SECONDS`). If that end is still ahead, the session is active until then and any
contact-loss deadline is cleared. If it has already passed, the evidence can only move a recorded
contact loss that began earlier to the point where the evidence ran out, restarting the recovery
window from there; it never makes a session active after the fact. Renewal is monotonic and
idempotent, so a duplicate delivery re-offers the same evidence without extending it, and a lease
already recorded by a newer call is never shortened. Every hook event except `SessionEnd` counts,
including `Stop` and `SubagentStop`, which prove the host was alive when they fired. Session-stream
history, future timestamps, predecessor routes, and evidence older than the lease plus the longest
configurable recovery window are not offered. The catalog binding is revalidated before renewal;
an ended session is not revived by observation replay, and terminal work is never reopened.

A host-declared child operation also holds contact. While the host lineage registry records a
native subagent start under a parent task without its stop, the recovery sweep renews the parent's
session for one lease per sweep instead of expiring it, because the host emits no parent event for
the whole run. The hold ends when the stop is recorded, and is bounded by the service policy
`LineageConfig.native_operation_hold_seconds` (3,600 seconds; not user configuration) for a host
that dies before reporting the stop. The hold publishes no event and never touches terminal or
ended work. The READY maintenance loop delivers queued host events before each ordinary recovery
turn and defers a due recovery while consecutive passes are still resolving rows, for at most one
extra interval.

Terminal work stays terminal. Resuming a task whose work is `closed`, `cancelled`, `abandoned`, or
`written_off` (`start` attach by session, attach or `create_or_attach` by pair) is refused inside
the start-catalog transaction with `SESSION_CONFLICT` reason `lineage_resume_work_terminal`, before
any session is reserved or the route rotates, so a session the caller still holds keeps reading
and publishing that task's history. A parent whose work is terminal is refused new child work
(delegation or self-registration) with reason `lineage_parent_work_terminal`, even when late
activity has restored its session. Both reasons carry continuation `lineage_successor_task`: keep
the held session for status, late publications, checks, and receipts, and start one successor
task with `mode=create`, a new `external_ref`, and a bounded handoff naming the predecessor for new
work and delegation. `lineage_parent_session_invalid` (the parent's own session is not current)
now maps to `lineage_state_refresh`. A replayed start whose route already names its session still
returns its recorded result after the task's work became terminal.

**Origin, acceptance, and creation.** `origin` is immutable: `parent_minted | self_registered |
host_observed`. Acceptance is parent-controlled: `pending → accepted` or `pending → rejected`,
and accepted relationships cannot later be rejected. `mode=delegate` creates `parent_minted` plus
`accepted` atomically. A host-observed signal is first a provisional annotation under one
correlation identity with pending acceptance and no bundle; it becomes one child only when accepted
delegation or cooperative self-registration binds to it. Host mapping remains evidence-gated in
#506–#508. The service owns child-dependency manifest stamping; host-observation inputs can enter
only through that service path, and ordinary client publication cannot self-award a manifest.

**Frozen rollup.** Before a parent check or receipt uses a child, the parent ledger records a
`child-dependencies-recorded` manifest containing child identity, origin, acceptance, frontier,
check/receipt identity, coverage, findings state, `lineage_authority_revision`, and optional
`membership_generation`. The lineage coordinator records changed child facts; receipt generation
only reuses recorded manifests and never records or refreshes one (#500). The parent receipt
projects direct children one level: current actionable findings on accepted children block
clean-completion wording, while the receipt is still produced and names the child and finding.
A child finding the child agent self-verified (issue #984, ADR-034) carries `self_verified: true`
on its manifest row (emitted only when true; it requires `resolved: false` and the kind's
`actionable: true`). The evaluator keeps it out of the parent's actionable findings and, on an
accepted child, records the standing gap `finding_self_verified` with its finding ids, so the
parent reads at best `insufficient_coverage`, never `unresolved_findings_remain`. The
`receipt-document` `1.3.0` child finding row carries the same optional `self_verified`, and
markdown/text render "self-verified by the child agent; FinishUP could not prove it" under it.
Both child finding rows carry every finding kind under its own name, the AI-powered review kinds
`code_defect`, `task_requirement_unmet` and `agent_criterion_unmet` included (ADR-040 amendment
of 2026-10-12). Pending-acceptance children and informational findings annotate only; accepted live children are
open gaps and accepted abandoned children are incomplete gaps. An unresolved informational
finding stays on the child row and does not replace an accepted lifecycle gap or a coverage or
verification blocker. The only informational kind, `ledger_stale_or_incomplete`, is emitted from
recorded ledger gaps, so a public child that carries it also carries an independent coverage
blocker. The no-gap lifecycle precedence is a kernel invariant. A grandchild is visible only through
its parent. Only a new manifest and qualifying recheck can clear a live-child gap in a later receipt.

**Lineage disclosure authority.** An accepted edge authorizes only (1) a service-side child read
to build the frozen manifest, (2) disclosure of bounded structural manifest facts into the parent
agent context, and (3) child-derived structural input to a parent semantic check. Each channel
keeps the child's provenance, category, never-send, task-scope, minimization, and authorization
restrictions. Project membership is unnecessary for lineage; cross-repository lineage is
prohibited in increment A. The candidate's Increment-B cross-repository path requires an explicit
current project-generation coordination grant at admission and delivery; `AuthorizationScope.contains()`
stays unchanged.

`HostLineageRegistryPort.latest_open_host_operation(parent_task_id, not_before, session_commitment)`
returns the newest first-observation time of a recorded start without its stop under that parent,
bound or provisional, only when the annotation's `last_session_commitment` exactly matches the
currently bound host session commitment. It ignores starts before `not_before`; it is the only
input to the in-flight contact hold and never mints, binds, or accepts a child. The service records
the commitment from an admitted event routed to the exact current session. A missing or stale
binding fails closed; after restart, the service may bootstrap the commitment only from the
durable observation route for that exact task/session pair. Task or project membership never
selects a host session. Native lifecycle events persist that route at admission, before optional
verification or advice work. An ended or rerouted predecessor remains structural evidence only;
its event cannot bind the successor, and a durable route's host-session commitment is a
compare-and-set fence that a later envelope cannot replace.

Session lease extension is an atomic, monotonic catalog operation. A newer observation, an ended
session, or a rotated session fence wins over a delayed renewal and cannot be overwritten by its
stale read. Callers revalidate the clock after awaited catalog or adapter work before committing
an active state.

`HostLineageRegistryPort.find_host_lineage_observation` resolves an already recorded host
observation within its installation, parent task, and host. It returns the persisted annotation,
refuses conflicting or ambiguous aliases, and never updates observation timestamps or session
ownership. Observation advice uses its bound child task ID, or its keyed correlation ID, alongside
the original envelope reference. Rebuilding advice cannot manufacture lineage or refresh children.

Explicit cooperative correlation selectors receive read-only registry validation before a child
attach consumes its handle. Contradictory or ambiguous selectors return a typed refusal without
rotating the child route. A transient final binding failure can replay the same durable start
operation and consumed handle; it never creates another child. A supplied parent-call selector
without the child identity needed to verify its commitment is refused.

Codex's admitted successful native child-start callback may bridge handle-only attachment to the
host annotation. It carries bounded child task/session/writer and parent task IDs; the service
checks them against the mapped child route and persisted parent relation before binding the native
subagent identity. This can record the correlation before the separate lifecycle hook arrives;
later hooks reconcile through the same aliases. It never mints a task or redirects parent advice.
Missing or contradictory identities remain coverage gaps. The observation mapping revision
`obs-ledger/1.7.0` includes an available parent tool-call discriminator in materialized subagent
identity. Incomplete hook/stream copies can retain separate evidence while the registry reconciles
one unambiguous annotation; two distinct parent calls must not collapse into one evidence event.
Historical mapping revisions keep their existing identity semantics. New subagent observations
do not implicitly reuse an old child-only operation whose missing parent-call discriminator
cannot prove equivalence; retained historical evidence is not rewritten.
The callback fields are additive in control `2.8.0`; frozen control `2.7.0` and earlier retain
their original shapes and reject those fields.

**Codex multi-agent v2 child identity (#754).** Under `multi_agent_version=v2` a delegated child's
own rollout header is an identity source: a `session_meta` whose `thread_source` is `subagent`
maps to a `SubagentStart` whose `subagent_id` is that header's `id` — the child thread. The
header's `session_id` is the *parent* thread and is never the child key; both spellings of the
spawning thread (`parent_thread_id` and `source.subagent.thread_spawn.parent_thread_id`) must
agree, and a header naming itself is refused. Only a header that declares `thread_source:
subagent` without a usable distinct identity earns `missing_subagent_identity`. That observation
belongs to the child's own session, so the annotation is filed under the parent task named by
admitted catalog lineage — never by the host's `parent_thread_id`, which cannot select a task —
and then bound to the observing child task, the same shape as the native child-start callback.
With no admitted lineage the observation keeps a bounded `host_lineage_child_not_found` gap. The
parent-side signal is unchanged: a `SubAgentActivity` item's `agent_thread_id` is the same child
thread, so the two sources reconcile into one annotation. `agent_path`, `agent_nickname`, and
`agent_message` `author`/`recipient` name an agent definition rather than a delegation instance;
they are never lineage identity or aliases. A `SubAgentActivity` `kind` of `interacted` is a known
non-lifecycle kind: it carries no phase and is not a coverage gap.

**Codex v2 child lanes under the shared root session (#841).** v2 writes one root `session_id`
into every thread of a delegation tree, so a delegated child's callbacks carry the parent's
session and its rollout is named by the child thread. A Codex tool, permission, prompt, `Stop`, or
compaction callback whose `transcript_path` (or `session_file`) is not the session's own rollout
may take its host child identity from that file's first line: only a safe owner-private `.jsonl`
beneath the Codex home's `sessions` root, whose v2 header declares a delegated child, whose
filename carries that child thread, and whose header names the callback's session as spawning
root. That identity is equivalent to a native `agent_id`: it publishes the child lane only through
a validated attach result and never selects a task, route, or annotation by itself. A transcript
that proves a delegated child but cannot name it for the session, or that contradicts a host
alias, makes the callback an explicit attribution gap and records the payload-free hook reason
`child_transcript_identity_conflict`. Session lifecycle and `SubagentStart`/`SubagentStop`
callbacks are never re-attributed. A callback on a validated host-identity child lane reconciles
that child's own rollout into the lane, so its header reaches the child-observed binding above.
`observe reconcile` resolves a child rollout through its header to the single lane derived from a
spawning session bound to the selected workspace alone and already mapped to another task, and
reports `mode: recovery_child_lane`. It never creates a mapping, task, or annotation; an
unprovable child rollout exits 20 with `observation_reconcile_failed:<reason>` for the closed
reasons `child_identity_invalid`, `child_parent_unmapped`, `child_route_missing`, and
`child_route_ambiguous`. Workspace-wide stream state and annotation counts are never binding
evidence.

**Project birth and coordination.** With `projects.auto_grouping` enabled, the second concurrent
live task in one repository materializes an implicit repository project. When disabled, the task
is admitted without creating a project row (#497). General or multi-repository projects are explicit
and amendable; implicit projects persist when concurrency drops to one. A repository may opt out through
`projects.auto_grouping` of automatic grouping and cross-task disclosure without erasing accepted
delegations, obligations, or receipt
dependencies. A fact enters coordination only when its source workspace's workspace-level
observation consent is active; consent for one worktree never covers another. General or
cross-repository coordination requires a
generation-bound `coordination_grants` authorization checked at admission and delivery. External
semantic dispatch bundling content from two repositories is outside this series.

`project dissolve` retires a general project and preserves its historical dependencies. Implicit
repository projects use `project opt-out` and `project opt-in`; attempting to dissolve one returns
`implicit_project_requires_opt_out` before any membership or generation changes.

**Superseded coordination context (#842).** A generation is superseded once the project records any
later membership generation or is dissolved. Before a new check that selects `coordination/0.1.0`,
the service closes each declared recipient context whose generation is superseded. It appends to
that recipient's own ledger one observation-authored, engine-derived
`coordination_context_recorded/1.0.0` for the same `detection_id`, `project_id`,
`membership_generation`, `recipient_task_id`, and `counterpart_task_id`. It carries
`gap_codes=["revoked"]`, empty `resource_identities`, `resource_count="0"`,
`source_attributable_paths=false`, and no `detail_ref`. Its event and operation identities follow
the ordinary context rule, so a retry replays. A replayed check operation skips this reconciliation,
and a failure before the closure append leaves the ledger unchanged for the next check. The closure
performs no project admission, disclosure, or delivery, and needs no current consent, grant, or
membership. The retired detector row becomes `generation_valid=false` in a separate durable
transition. If that transition fails after the closure commits, the next reconciliation retries it
from the recorded closure without appending a duplicate marker. In a frozen check, a delivery with a
`revoked` closure derives no `coordination_overlap` finding in any scope. The earlier finding
resolves under the ordinary qualifying-check rule, and its status and receipt resolution explanation
names the superseded generation instead of a disposition. A `coordination_obligation_declared` or
`coordination_disposition_recorded` publication naming a superseded generation is refused with
`INVALID_REQUEST` and `reason_code=coordination_generation_superseded`, continuation
`coordination_superseded_recheck`. The refusal appends nothing; `coordination_admission_required`
remains for a current generation that fails admission.

When an admitted task has no revealable attributable path, coordination records one bounded
per-task coverage row with `coverage=unobservable` and `gap_code=not_observable`. The row carries
only the task, project generation, and closed gap vocabulary. It is not a detection or delivery,
and it contains no counterpart or resource identity; an unconsented, stale, dissolved, or
out-of-project task produces no row.

Coordination inputs are typed payload fields: file and source requested items, attempted edit
items, obligation identities, and coordination declarations. `LedgerCoordinationInputProvider`
admits the source under the same consent, source-policy, membership, and grant checks as delivery
before it reads them. It then reads them through one `payload_read` lease, so a cold runtime entry
yields the same input as a warm one. A task that is not currently admitted contributes no input
and no row, and it does not abort the sweep for admitted tasks. This includes a task whose runtime
cannot be opened to confirm its consent. If an admitted task's input read fails during a sweep,
that task is kept out of pair detection and receives the same bounded coverage row. This also
applies when the later payload lease used to revalidate declaration ownership fails; successful
input loading alone does not establish that ownership can still be read. One diagnostic, `application.coordination`/`coordination_input_unavailable`, records only the
exception-class token and a correlation ID. The other pairs are still detected, and the next
sweep retries. A post-publish sweep that fails as a whole never fails the committed publication;
it records `application.service`/`project_coordination_sweep` with the request ID.

Optional project notes on a check use the same authority boundary. Missing consent, a missing or
revoked grant, a changed generation, or a retired membership suppresses that project's notes without
an internal-failure diagnostic or a fallback disclosure attempt. Independently admitted projects
remain eligible; the optional note does not change the recorded check verdict.

Detection detail is a separate encrypted object owned by one participant. A project status read
may dereference it for either affected task only after both participants pass current-generation,
workspace-consent, and source-policy checks; the recipient projection then applies its own sink
policy to the relative-resource content. The typed project detection row carries either the
approved repository-relative path tuple or a bounded omission. Catalog rows, delivery events, and
MCP text summaries retain only identities, counts, digests, and allowlisted gap codes; they never
carry raw paths.
The ordinary advice view carries the counterpart task and an exact project/detection/generation
selector; its resource field follows the same sink-bound hydration and omission rules.

**Bounded reversal and retired guards.** Live, consented project membership may disclose bounded
sibling task identity and state through the service status projection. It never authorizes attach,
resume, or task selection. Possession of a workspace reference alone remains insufficient to
discover or attach another task. When no usable persisted recovery selector applies, automatic
`create_or_attach` admits a new pair beside an existing task. Task-owned inspection snapshots and
session advice remain bundle-resident; installation coordination uses the catalog without
transferring their content or authority.

**Historical no-new-tool boundary.** The following paragraph records the pre-#953 series. At that
point its six workflow operations were `start`, `publish_work`, `check`, `status`, `receipt`, and
`respond`, plus the existing read-only `read_guidance` support tool; lineage/project behavior
composed those surfaces without adding another one. The 2026-09-05
pre-trim snapshot was 204,404 bytes (policy) and 204,658 bytes (strict) against 205,000 bytes.
After #504 step 0, the source baseline is 148,308 bytes (policy) and 148,562 bytes (strict),
including 12,385/12,409-byte initialize instructions and 8,218/8,304 bytes of descriptions; it
leaves 56,692/56,438 bytes for later schema growth. These are reviewed baselines, measured before
later series changes. Installed host capability claims remain separately evidence-bounded.

The earlier consolidated 0.3 descriptor measurement was 168,941 bytes (policy) and 169,195 bytes
(strict), below the then-reviewed 205,000-byte ceiling. That is a historical pre-integration
measurement: it predates the current-main guidance and descriptor text carried by the merge.

The current 0.3 descriptors advertise `start-request/1.1.0`, `publish-work-request/1.2.0`,
`check-request/1.1.0`, and `status-request/1.2.0`, including separate child attach,
self-registration, lifecycle, and coordination declaration and disposition examples. The current
packaged measurement after #499/#507 is 219,369 bytes (policy) and 219,623 bytes (strict), comprising 19,264/19,288
bytes of initialize instructions, 12,958/13,044 bytes of tool descriptions, and 71,563 bytes of
advertised input schemas. The reviewed aggregate ceiling is 220,000 bytes; the policy route's
longest 1,000-byte destination disclosure measures 226,376 bytes and the derived disclosure ceiling
is 227,000 bytes. Public lifecycle families are advertised; service-stamped delegation declarations
and child manifests remain excluded from ordinary publication.
The #499/#507 guidance consumes 3,850 aggregate bytes over the integrated 215,519/215,773-byte
baseline; no MCP tool or advertised input-schema field is added by this repair.

### Immutable objects and keys

`ObjectStorePort` methods are:

- `commitment_for(data: bytes, kind: ObjectKind) -> str` — keyed, domain-separated, and
  non-publishing, used to build a logical request digest before object publication;
- `stage(ObjectSource, ObjectMetadata) -> StagedObject`;
- `finalize(StagedObject) -> ObjectRef`;
- `abandon(StagedObject) -> None` — idempotently remove the exact caller-owned temp *and* finalized
  bytes only while the caller can prove that its reference has not been submitted to a durable
  owner; a byte mismatch fails closed and an abandoned stage cannot be finalized later. Both
  locations are attempted even when one fails, so a temp-path fault cannot strand the finalized
  copy; the first failure is raised and the stage stays un-abandoned so a retry re-attempts both.
  A local captured-content manifest row is a durable owner. The observation coordinator abandons a
  just-finalized captured-content object through `abandon_preappend_objects` only after a lookup
  proves that row does not name it (ADR-003, #571 / #550). A committed row forbids abandon. A
  failed lookup is not that proof. Abandon failure is logged as `observation_object_abandon_failed`
  and does not replace the caller's store error; generation-fenced GC remains the fallback;
- `resolve_verified(object_id, envelope_digest) -> ObjectRef` — bounded exact finalized-object
  resolution for catalog-pinned START crash resume; deterministic verification failures raise
  `ValueError("object_verification_failed")`, while environmental I/O re-raises `OSError` for the
  START application to classify as retryable `STORAGE_UNSAFE`;
- `open_verified(ObjectRef) -> AsyncIterator[bytes]` — missing, tampered, or otherwise
  unverifiable objects raise `ValueError("object_verification_failed")`; environmental I/O
  during an otherwise well-formed open re-raises `OSError`;
- `sweep_orphans(ObjectRootSnapshot, now) -> int` — delete only safety-window-eligible objects
  absent from every owning root while the bound route/bundle/privacy generations remain unchanged.

`ObjectKind` is `event_payload`, `captured_content`, `semantic_case`, `semantic_response`,
`operation_result`, `start_result`, `check_resume`, `deterministic_result`, `receipt`,
`import_source`, `import_source_manifest`, `import_plan`, `import_report`, `import_stderr`,
`import_quarantine`, `capability_evidence`, or `privacy_audit`. A logical preflight can avoid routine retry orphans; a race may still leave
an encrypted unreferenced object, which delayed safe GC handles.

`ObjectKind.import_stderr` is commitment-only in v0.1: `commitment_for` accepts it as the stable
K_commit domain, while `stage`/`finalize` reject it because raw stderr retention is forbidden.
`ObjectKind.privacy_audit` contains task-bound prepared privacy/audit content only; a catalog
privacy row is an explicit non-ledger live root. Taskless v0.1 privacy decisions are structural-only.

`ports/objects.py` exports `MAX_OBJECT_HEADER_BYTES=16384` and an exact
`OBJECT_COMMITMENT_DOMAINS` entry for every kind. Each entry is the ASCII bytes
`b"yoetz/object/<exact_enum_spelling>/v1\x00"`, enumerated individually in that owner; no runtime
string transform is authoritative. Commitment is exactly `hmac-sha256:` plus lowercase hex of
`HMAC-SHA-256(K_commit, domain || raw_plaintext_bytes)`. Callers, not the object port, canonicalize
structured content. `StagedObject`/`ObjectRef` use `envelope_digest` for SHA-256 over the complete
final frame.

`ObjectRootSnapshot` is the service-internal, path-free union of task-ledger inventory, importer
rows, catalog `PrivacyAuditObjectRoots`, and maintenance pins for one exact task/route. It binds
bundle/route/privacy-root generations plus each source-set digest. GC must revalidate the snapshot
through deletion; missing ledger inventory never makes a catalog-rooted `privacy_audit` object an
orphan.

`yoetz-object/1` is exactly `b"YZO1" | 0x01 | u32be(header_length) | JCS UTF-8 header |
12-byte payload_nonce | plaintext_size bytes ciphertext | 16-byte tag`, with header length
`1..16384`, no trailing bytes, and exact header fields/constants frozen in `ports/objects.py`.
Each fresh 32-byte payload DEK performs one AES-256-GCM encryption and is wrapped to exactly 40
bytes with nonce-free AES-256-KW (RFC 3394) under `K_wrap`; no wrap nonce or embedded checksum exists.

`KeyStorePort` is service-internal. Its async methods are `load_bundle_keys(bundle_id) ->
BundleKeys`, `create_bundle_keys(bundle_id) -> BundleKeys`, and `wrap_recovery(bundle_id,
recovery_secret: RecoverySecret) -> RecoveryArtifact`; its synchronous
`installation_mac_handle(purpose: MacKeyPurpose) -> MacKeyHandle` accepts only
`catalog_lookup|log_correlation|privacy_audit`. Shared types are `BundleKeys`, `WrapKeyHandle`,
`MacKeyPurpose` (`bundle_commitment|catalog_lookup|log_correlation|privacy_audit`), `MacKeyHandle`,
`WrappedDek`, `RecoverySecret`, `RecoveryArtifact`,
`KeyStoreError`, and `KeyStoreReason`. Reasons are exactly `vault_locked`, `key_missing`,
`key_id_mismatch`, `unsupported_backend`, `backend_unverified`, `recovery_artifact_missing`,
`recovery_secret_wrong`, `recovery_artifact_tampered`, `recovery_format_unsupported`,
`machine_bound_key_missing`, `recovered_key_cannot_decrypt`, `stale_key_handle`,
`mac_purpose_mismatch`, and `mac_domain_forbidden`. Raw IVK, BMK, installation/bundle derived-key,
DEK, credential, unlock, and recovery bytes never cross an opaque handle
boundary. `RecoverySecret` is a one-shot `SecretHandle` restricted to
`SecretPurpose.portable_recovery`; no string/bytes constructor exists.

`BundleKeys` contains `K_wrap` and `K_commit` operations only. Bundle derivation uses exact
HKDF-SHA-256 salt `b"yoetz/bundle-key-root/v1"`, exact ASCII infos `b"yoetz/kek/v1"` and
`b"yoetz/commitment/v1"`, and output length 32. `WrapKeyHandle` exposes only RFC 3394 wrap/unwrap
of an exact 32-byte DEK; `WrappedDek` is algorithm `aes-256-kw-rfc3394` plus exact 40 wrapped bytes
and has no nonce. The sole `K_lookup` is installation-scoped. On each unlock the vault derives
`K_lookup`, `K_log`, and `K_audit` from the stable IVK using HKDF-SHA-256 with exact salt
`b"yoetz/installation-mac-root/v1"`, exact ASCII infos `b"yoetz/catalog-lookup/v1"`,
`b"yoetz/log-correlation/v1"`, and `b"yoetz/privacy-audit/v1"`, and output length 32; none is stored
as a separate vault record. One opaque `MacKeyHandle` type is bound at minting to purpose,
service/vault generation, optional bundle generation, and an exact domain allowlist. Catalog lookup
owns
`yoetz/start-title/v1\x00|yoetz/workspace-ref/v1\x00|yoetz/external-task-ref/v1\x00|yoetz/repository-privacy/v1\x00`;
log correlation owns
`yoetz/session-log-id/v1\x00`; privacy audit owns `yoetz/privacy-egress-request/v1\x00`. Cross-
purpose/domain use fails before MAC execution, and relock invalidates every handle.
Every `MacKeyHandle.mac(domain, message)` computes exactly
`HMAC-SHA-256(bound_key, domain || message)` after byte-exact allowlist validation; it adds no
encoding, length prefix, hash prepass, normalization, or delimiter.

### Trusted local service, ordinary control, and secret memory

`ControlClientPort` is the only ordinary CLI/MCP/UI route to the trusted service. It exposes
`connect`, `call(ControlRequest) -> ControlResult`, `service_status() -> ServiceStatus`, bounded
CLI/UI-only `lock`/`stop`, and `close`. Shared closed types are `ControlClientKind`
(`cli|mcp_bridge|ui`), `ControlMethod`, `ControlRequest`, `ControlResult`, `ServiceState`
(`starting|locked|unlocking|ready|draining|failed`), and `ServiceStatus`. The method registry has
exactly thirty-one calls: the six workflow operations plus twenty-five support/preview/execute,
lifecycle, observation-control, and CLI/UI-only methods. The privacy subset is exactly
`privacy_get_setup|privacy_get_effective|privacy_propose_policy|privacy_tighten_policy|
privacy_pending_list|privacy_receipts_list|privacy_receipts_get`. The observation subset is exactly
`observation_ingest|observation_status|observation_pause|observation_resume|observation_revoke`
(local CLI/UI only; never MCP tools — the public MCP surface remains the six workflow tools
plus read-only `read_guidance` and `closure_prepare`).
Observation status uses a versioned body containing `schema_version`, `request_id`, and `query`;
pause, resume, and revoke use `command` in place of `query`. Their successful control responses
contain `schema_version`, the same `request_id`, and `status`. The support adapter translates these
wire envelopes to the domain query or command; the observation-ingest envelope is separate.
It has no privacy decision, unlock, secret, credential, key-handle, decrypted-object,
operation-body arbitrary-path, or policy-loosening field or method. The versioned handshake locator
below is the sole narrow path-bearing exception. `service_status` is available while locked;
task operations are not. MCP cannot invoke lifecycle, privacy-control, or observation-control
methods.

`ServiceStatus` (wire schema `service-status-1.0.0`, closed to unknown fields) describes the
singleton service holder only, and carries no approved-check sandbox field. Approved-check sandbox
availability — `CheckSandboxAvailability(status, mechanism, reason, remediation)` with the closed
reason set `ready|bwrap_missing|bwrap_unusable|sandbox_exec_missing|platform_unsupported` — is a
live capability probe of the process that asks, not a property of that holder, so it is reported by
the invoking client on exactly three surfaces: `finishup observe checks status` (`sandbox`),
`finishup setup status --json` (`platform.check_sandbox`), and `/doctor`. This is the recorded revision of
issue #720's "report it in `finishup service status`"; the rationale and the Linux/WSL operator detail
live in [`runbooks/linux-and-wsl.md`](runbooks/linux-and-wsl.md#approved-check-sandbox).

The versioned ordinary-control hello may carry one optional trusted `workspace_locator` derived by
the client itself: CLI/UI use their actual process working directory and the MCP bridge uses its
configured/session working directory. It is never populated from an operation body or public
`workspace_ref`. The service resolves symlinks, resolves a Git worktree to its canonical common
repository root (or a non-Git workspace to its resolved directory; for a non-root user, a checkout
whose nearest `.git` or working tree root owns, which Git refuses as "dubious ownership", gets the
`directory` identity of the checkout's top, `adapters/repository_identity.root_owned_checkout`,
the same from any directory beneath it and equal to the locator workspace binding gives hooks, and
Git is not run against it: ADR-007, 2026-10-14, item 4; check-time change capture refuses that
checkout as `unsafe_root`; another non-root account's checkout stays
`repository_identity_unavailable`), computes the installation-keyed
`repository_privacy_commitment`, and keeps no other copy of the raw locator. The resulting
`ControlSession` carries `RepositoryPrivacyContext(commitment, identity_kind)` plus, in service
memory only and outside its equality and `repr`, the exact `workspace_locator` the commitment was
derived from. That locator is read only by the ADR-031 check-time change capture of the same
connection's `start` and `check` calls; it is never stored, logged, projected or returned.
Branches and
linked worktrees share one commitment; independent clones and unrelated repositories do not. An
older hello decoder or omitted locator produces an unbound session and cannot create, migrate, or
consume repository disclosure authority.

The version 2 hello also carries one closed optional `presentation_context(render_mode,
output_is_controlling_tty)` produced by the authenticated local client from its actual rendering
path. Omission defaults to machine-readable/non-TTY. The daemon retains these facts on the
`ControlSession` and constructs the service-internal `ClientProjectionContext` for every connected
call; request bodies cannot replace them. An interactive CLI privacy flow sends human-readable plus
its foreground controlling-TTY fact. These are presentation facts only: since ADR-009 round 3 none
of them selects `local_human_view`, and every connected call is `agent_context` unless the daemon
consumed an `owner_receipt_view` grant for that exact receipt call.

The `privacy_get_setup` version 2 result carries `PrivacySetupSnapshot`: exactly the composed policy,
bound repository-backed workspace scope, `authority_digest`, `grant_state`, and `migration_state`
beside the setup projection. The snapshot traverses the same generic local client-result privacy
projection and reserve/complete disclosure-receipt path as other ordinary local results; its closed
wire branch therefore requires `privacy_projection`. Reading it grants no authority:
the matching version 2 `privacy_propose_policy` request still binds its candidate and any compound
transition members to that `authority_digest`, not merely to one current policy digest, and the
separate trusted decision remains mandatory. `privacy_get_setup`, version 2
`privacy_get_effective`, and version 2 `privacy_propose_policy` receive only the service-derived
`RepositoryPrivacyContext` from their control session; the ready application facade must forward
that exact context to the bound privacy handler and must not accept a body-supplied replacement.
Decoders for the version 1 setup/propose bodies remain registered for compatibility,
but a version 1 request cannot create a repository row, consume a migration entitlement, or
authorize standing external LLM work; under repository-grant mode it fails closed with bounded
upgrade guidance.

Ordinary-control sessions are peer-authenticated over the fixed owner-only AF_UNIX control
endpoint. Public connection liveness (enforced by the daemon, not a wire field): handshake must
complete within **5 seconds** (entire read/write, including partial frames); after handshake, a
session with no active requests may remain inactive for at most **5 minutes**, after which the
stream is closed and the listener admission slot is released. Active requests exempt the session
from the inactive timer until the final in-flight call completes; long-running calls are not
cancelled solely for lack of a subsequent frame. Each control-result write is also wall-clock
bounded (**5 minutes**): a peer that stops reading cannot retain an in-flight call entry (and
thus the inactive-session exemption) indefinitely via send backpressure.

The ordinary client independently bounds each connect-plus-handshake attempt to **5 seconds** and
closes a half-open stream on expiry. On-demand startup has one **30-second** monotonic budget that
includes its initial attempt, spawn, and polling; an accepted but silent existing endpoint is
reported unavailable rather than causing a second daemon to be spawned.

The handshake pins the exact schema-manifest digest on both sides. When a listening
service can decode the peer's hello as a known control-hello shape but the digest does
not match, it answers with a hello-result carrying **this** installation's digest and
then closes without admitting a session. The client names an answered digest mismatch
`manifest_mismatch` and a silent close (unknown hello shape, or a peer that still
closes without answering) `handshake_rejected`. An answered `manifest_mismatch` maps to the
retryable `ControlError` reason `service_incompatible` (public code `SERVICE_UNAVAILABLE`). A
silent close proves nothing by itself, because a service of this very installation also closes
when its own side of the handshake fails (#1040 follow-up, below); the client reads the singleton
stamp (`_stamp_identity` in `finishup.service.client`) and reports `service_incompatible` only on
evidence: a present, validated field that differs from this installation's (a well-formed
`schema_manifest_digest`, or a `service_version` that parses as a package version). A stamp with
neither identity key at all is not evidence either: FinishUP 0.1.x stamped only `pid` and
`instance_id`, but writers from 0.2.1 until the #1040 follow-up wrote both fields when the schema
manifest could be read and neither when it could not, and such a stamp lasts as long as its
process, across an upgrade, so absence cannot tell an older installation from a compatible one
(a current writer always writes `service_version` and adds the digest when it can read it, so a
current service never writes that shape). A holder stamped with this installation's identity,
one whose stamp cannot be read, one whose identity fields are only partly readable (a key absent
or present but invalid, beside fields that match), and one stamped without any identity key
yields the non-retryable `ControlError("service_unavailable", phase=...)` described under "A
handshake the service failed", whose remedy is `finishup service diagnostics`: missing information
is never read as another installation. `finishup service status
--json` emits `service_incompatible` plus the stamped holder identity and a `correlation_id`
joinable with `finishup service diagnostics --correlation-id`. Older
pre-2.2.0 CLIs that lack `handshake_rejected` still decode the answered hello-result
and fail on the digest themselves (`protocol_mismatch` in those binaries). The
singleton lock stamp carries the holder's `pid`, `instance_id`, `service_version`, and
`schema_manifest_digest` (bounded, advisory; a missing or invalid field is read as unknown,
and `SingletonHolder.identity_fields_absent` marks a stamp that has neither key). The same
evidence rule selects replacement candidates: only a demonstrated mismatch is signalled
automatically. A holder stamped without any identity key is replaced only by the owner's explicit
`finishup service restart` (`supersede_incompatible_service(replace_legacy=True)`), which may also
replace a newer holder; it is never replaced by on-demand startup, a hook or a bridge.
On-demand startup — the MCP bridge's path
and `finishup service restart` — treats an incompatible holder as an upgrade to complete: it records a
`service_supersede` diagnostic, sends the holder its ordinary bounded-shutdown signal, waits for the
lock to be released inside the same 30-second budget, then spawns and connects to a successor of
this installation. It never signals a process it cannot identify through the owner-only stamp, a
holder whose stamped identity equals this installation's, a holder whose identity fields are only
partly readable or absent (only the explicit restart may replace an identity-less stamp), a holder
whose stamped `service_version`
is newer than this installation's (only the explicit `finishup service restart` may replace one), or
anything on Windows. A holder already shown to be another installation (a validated field that
differs) whose replacement is refused for one of those reasons, or that outlives the budget,
surfaces as `service_incompatible`; the bridge message then names `finishup service restart`, except
for a newer holder, where it asks the user to reopen the session. A same-identity, partly readable
or identity-less holder never reaches this path: its unanswered hello is the non-retryable
`service_handshake_failed` ("A handshake the service failed", below), whose remedy is
`finishup service diagnostics`. `finishup service restart`, given that error, replaces the holder only
when its stamp carries no identity key, and otherwise reports it unchanged. The MCP bridge also retires a *compatible* holder
whose hello reports an older package version than the bridge's, through the same stamped
bounded-shutdown path, so the first session opened after an in-place `finishup upgrade --accept`
switches to the new package. Until that transition, already-open processes use retained runtime
copies; the transition may require older incompatible sessions to reopen (ADR-007,
2026-09-24 amendment). When no holder can be identified it keeps using the compatible service.
Plain `connect_service` (ordinary CLI commands and hook drains) never starts or supersedes.
Consented hook auto-attachment uses the same fixed on-demand launcher with
`supersede_incompatible=False` and a one-second connection/startup budget. It reuses an
already-stamped compatible starting holder only while an owner-only nonblocking flock probe
confirms that the singleton is still held; an unheld stale stamp is ignored and the fixed
launcher makes a normal flock-protected start attempt. A live incompatible or unknown stamped
holder is refused without signalling it. The authenticated handshake remains authoritative; the
stamp is only a pre-spawn hint. Startup and the auto-attach `start` share the existing five-second
RPC budget; turn-boundary retries retain their one-second outer budget and reserve part of it for
the start RPC after a shorter connector arm. A budget expiry leaves attachment incomplete and
queued structural rows pending. SessionStart context distinguishes `service_unavailable`,
`service_incompatible`, `service_handshake_failed` (a running service of this installation closed
the hello; the hook diagnostic reason of the same name), `auto_attach_conflict`, and an incomplete
mapping without asserting
`mapping_missing`, and directs the agent to explicit `start` before
material work, then its exact typed continuation. Hook exit zero is graceful degradation, not
proof of service readiness or a mapped task. No transient content is reconstructed from queued
structural envelopes. This path conveys no initialization, unlock, privacy, or takeover authority.
Bridges of the stale installation reconnect and are refused in turn until their session is
reopened, and never replace the newer service: the one per-user endpoint belongs to the newest
installation in use. Installed bridges and services run from retained release copies, including
code, dependencies and resources, so package replacement does not change the bytes available to
an open process (ADR-007). Entering a retained copy refuses an installation it cannot trust or
serve with an ownership token, `adapters/release_runtime.OWNERSHIP_TOKENS` =
`release_runtime_group_writable|release_runtime_world_writable` (another account can write the
runtime) `|release_runtime_not_owned` (its `.<prefix>-releases` directory belongs to another
account, or is absent from a parent another account owns and this user cannot write: a runtime
another account installed); `installed_runtime_refusal()` reports the same tokens read-only, and
`cli/runtime_refusal.runtime_refusal(token, hook=)` is the one text every surface prints (terminal
commands name the repair and, for `release_runtime_not_owned`, the directory and the repair that
fits whose installation and directory it is; hooks exit 20 with no stdout and no local path).
`cli/runtime_refusal.connect_refusal()` is the same check as `(token, next step)` for every connect
path (`setup run` with or without `--host`, the full-screen interface's first run and `/connect`,
`integrate codex mcp preview|install` and so the prompt-loop menu, `recommend accept
codex-plugin-activation`, `integrate claude plugin`
connect actions, `integrate cursor plugin preview|install`, `integrate cursor project-mcp
preview|install`, and `cli/host_connection.apply_selected` for a connect); disconnect, removal,
their previews and status never consult it. The MCP bridge supplies a
default **30-second** call deadline for `start`, `publish_work`, and `status`, a default
**50-second** deadline for `respond` and `receipt` (below the common 60-second host MCP tool
limit, so the bridge's typed timeout reaches the agent first), and a default **300-second**
deadline for `check` (a `check` with `mode: inspect` is a read and takes the `status` deadline,
ADR-047); these use the existing private `deadline_ms` envelope field and do not
change the public workflow-tool schemas. The bridge environment may override them in integer
milliseconds, clamped to 1,000-900,000: `FINISHUP_MCP_DEADLINE_MS_<TOOL>` (for example
`FINISHUP_MCP_DEADLINE_MS_RECEIPT`) sets one tool, and `FINISHUP_MCP_DEADLINE_MS` sets every tool except
`check` (an inspection follows `FINISHUP_MCP_DEADLINE_MS_STATUS` and the global variable, never
`FINISHUP_MCP_DEADLINE_MS_CHECK`); an unparsable value keeps the default. Raising a deadline above the host's own MCP tool
timeout only lets the host give up first. A timed-out write has an unknown outcome: the bridge
must preserve its retryable failure shape, say that it may already have committed, and direct the
caller to retry with the same `request_id` (and operation status where applicable). A timed-out
read may simply be repeated. For a timed-out `publish_work`, `respond` or `receipt`, the bridge
probes `status view=operation` once (5-second budget) for that exact `request_id`. When the
operation is already `complete`, it replays the unchanged request once under the same
`request_id` and returns the stored outcome instead of the timeout. Otherwise the timeout carries
a pollable handle in `safe_details`: `replay_request_id` (the value for
`filter.operation_request_id`), `session_id`, `writer_id`, `view: operation` and the probed
`state` (`absent`, `pending`, `quarantined` or `unknown`). This is an unknown write outcome, not a
failed commit. CLI callers retain their explicit `--deadline-ms` override.

The private `ControlCallRequest` envelope may carry `route_profile=policy|strict` only for `check`
and `status`. It is set by the MCP bridge from its immutable process profile, is absent from public
operation request models, and is rejected on every other control method. `strict` prevents
`check` from requesting the AI-powered review (`semantic`) runtime capability or dispatching an
evaluator; an agent cannot
weaken or select this field.

`ControlError` carries one bounded reason, a `retryable` flag, and an optional service-minted
`correlation_id`. The port and hook diagnostics share one lightweight closed reason vocabulary;
`invalid_request` denotes a malformed local request and is terminal for observation draining.
The closed reason set includes `endpoint_unsafe` (local AF_UNIX path/mode/peer
safety refusal). The ordinary client preserves that token instead of folding it into
`service_unavailable`. The MCP bridge maps it to public `SERVICE_UNAVAILABLE`, `retryable=false`,
and `safe_details.reason_code=endpoint_unsafe`, with copy that names the endpoint-safety class and
never a socket path. Unsafe and untrusted endpoint copy forbids retry before local repair and then
preserves same-`request_id` replay. The CLI control-failure helper is unchanged: it still projects
the public code and does not add a separate unsafe-endpoint guidance line.

**Write-side classification (issue #678).** `frame_invalid` names a frame that failed validation,
encoding, parsing, or correlation. A control frame is encoded before it is written, so a failure
raised by the stream during the write states something about the connection, not about the frame:
the bounded transport reason travels unchanged and the ordinary client classifies it exactly as it
classifies a failed connect (`endpoint_unsafe` and `peer_untrusted` preserved, everything else
retryable `service_unavailable`). A send failure the transport itself did not classify becomes the
bounded protocol reason `transport_failed`, whose public code is `SERVICE_UNAVAILABLE` and which
never carries raw exception text, a path, or peer data. Both peers share the one write helper, so a
failed response write is classified the same way; the daemon records it as a bounded
`control_response_write` diagnostic and ends that call rather than reporting a malformed frame.
That record carries only bounded structural context so an abandoned write can be attributed
(tb4n2 NEW-8, issue #1019): `control_method` (the closed wire method), `client_kind` (the
handshake kind: `cli`, `mcp_bridge` or `ui`), `duration_ms` (dispatch start to the failed write)
and `request_id` only when the body carries a valid public `req_` id; never the body, the rpc id or
peer data. A
caller whose valid request could not be written is therefore never told `INVALID_REQUEST`, and every
pending future failed by the resulting connection teardown — including the future of the call whose
own write failed — is consumed, so a failed send emits no unhandled-future report.

The MCP bridge maps every typed `ControlError` reason onto a public error through the public-error
recorder (`{tool}_public_error`) with sink `reason` equal to the control-reason token (or
`accepted_but_unresponsive` for an accepted-but-silent listener). `exception_control_error` and
`{tool}_internal_error` remain only for genuinely unexpected defects. Absent service uses
`SERVICE_UNAVAILABLE` with the sanctioned `finishup service run` supervisor copy and same-`request_id`
replay; an accepted-but-unresponsive listener uses distinct copy that forbids `finishup service run`
and names `finishup service status` / `finishup service stop`. `service_incompatible` and
`protocol_mismatch` share the `finishup service restart` copy and public `SERVICE_UNAVAILABLE`, and
are told apart by `safe_details.reason_code`. That MCP `SERVICE_UNAVAILABLE` mapping for
`protocol_mismatch` is deliberate: the CLI helper still uses `public_error_code_for_control_reason`,
which keeps `protocol_mismatch` as `INVALID_REQUEST`.

**Typed service startup failures (issue #1040).** Every failure of `finishup service run` before or
while it serves writes one durable diagnostic record (component `service.daemon`, operation
`service_startup_failed`) with `phase` the startup stage — `import`, `configuration`,
`composition`, `activation` (endpoint publication, after ready activation when the vault unlocks)
or `serving` — `reason` the reviewed exception-class token (`exception_not_implemented_error`, or
`exception_unavailable` for an unlisted class), `origin` the innermost `finishup` frame, and
`reason_code` the exception's own closed refusal token when it has one (a lifecycle, path-safety,
instance-identity or configuration reason; or an endpoint, storage, host-lineage or public-error
refusal — `runtime_directory_unsafe`, `endpoint_in_use`, `storage_path_unsafe`,
`host_lineage_migration_required`, `migration_required`, … — which stays an unexpected failure).
An unexpected failure prints `internal_error: the service could not start (stage: <stage>;
<exception token>[; <reason_code>][; at <origin>]); correlation_id <err_…>` (`stopped
unexpectedly` for `serving`) and exits 70; typed refusals keep their existing lines and exits,
and a configuration refusal prints `invalid_request: <reason_code>` and exits 2 as every other
command does. Losing the singleton to a live service (`service_already_running`) is not
recorded. On-demand start (`finishup.service.client`) passes the hidden `service run
--startup-correlation-id <err_…>` so the child records under an id its spawner chose; when that
child exits having recorded a failure, the spawner stops waiting and raises `service_unavailable`
with `phase` set to the stage, `correlation_id` set to the record's id and `retryable: false`. The
MCP bridge maps it to `SERVICE_UNAVAILABLE` with `safe_details.reason_code`
`service_start_failed` and `safe_details.phase` the stage (the text channel reads
`Reason: service_start_failed (stage: <stage>).` plus the fixed remedy), reusing the child's id
without recording a second one; the message also names the exception token and origin. The CLI
renders `service_unavailable: the local service exited while starting (<stage; class[;
reason_code]; origin>); correlation_id <err_…>`. It is an availability failure, so the latch
above applies. Setup's on-demand starts (`setup vault`, `setup llm --set`, the interactive
wizard), its restart after a provider binding change and `observe drain` print that same CLI line
on stderr before their own unchanged result and exit code; that restart stops at the first such
failure instead of spawning again.

**A handshake the service failed (#1040 follow-up, tb4n5).** Once the vault is ready, the service
resolves the hello's `workspace_locator` to a repository identity during the handshake. When that
fails (a `RepositoryIdentityError` such as `git_version_unsupported` or
`repository_identity_unavailable`, or any unexpected exception) `server_handshake` closes the
connection without answering, admits no session, and raises `HandshakeServiceFault` (control
reason `handshake_service_fault`, server-only) carrying the closed refusal token or, for an
unexpected exception, that exception as its cause. The daemon records it once: a typed refusal as
public error `handshake_service_fault` with `reason_code` the token (component `service.daemon`,
operation `control_handshake`); an unexpected exception through the unexpected-exception record
with its class token, origin and `phase: handshake`. Neither record carries the locator, a path,
Git output or stderr. The client sees only `handshake_rejected` and classifies it by the singleton
stamp (above): for a holder of this installation, or of unreadable, partly readable or absent
identity, it records
`service_handshake_failed` (component `service.client`, operation `control_handshake`) and raises
`ControlError("service_unavailable", retryable=False, phase=<phase>, correlation_id=<that
record>)`, where `phase` is `handshake`, or `handshake_git_version` when the hello carried a
workspace locator and the system Git (the first `git` on `os.defpath`, which the service uses) is
older than 2.25 (`finishup.protocol.errors.SERVICE_HANDSHAKE_PHASES`). On-demand startup reports it at
once: it neither supersedes the holder nor spawns a successor, and its poll loop does not wait out
the budget. The MCP bridge maps it to `SERVICE_UNAVAILABLE`, `retryable: false`,
`safe_details.reason_code` `service_handshake_failed` and `safe_details.phase`, adding
`safe_details.continuation` `system_git_upgrade_required` for `handshake_git_version`; its message
never names another installation or `finishup service restart`, and asks for `finishup service
diagnostics` (or a Git 2.25 or later system Git). The CLI prints `service_unavailable:
service_handshake_failed: …` with the holder pid and correlation id (`--json`: `reason`
`service_handshake_failed`, `phase`, `retryable: false`, `correlation_id`, `holder`), and
`finishup service restart` reports it instead of signalling the holder, except that it replaces a
holder whose stamp carries no identity key (the one path allowed to). It is an availability failure,
so the latch below applies.

**Availability latch (issue #469).** The bridge treats the control reasons `service_unavailable`,
`service_incompatible`, `protocol_mismatch`, `endpoint_unsafe`, and `peer_untrusted` as facts
about its host binding (this bridge process, its route profile, and the fixed endpoint), not about
one request. The first such failure is returned with `safe_details.availability =
"terminal_unavailable"`, `host_profile`, and `route_profile` beside the existing `reason_code`, and
is latched in the bridge's private client slot together with the request id, the public error, its
correlation id, and the advisory singleton-holder stamp observed at that moment. Concurrent first
arrivals before that result share one on-demand attempt: a slot-scoped in-flight gate parks later
calls until the first probe completes, then they inherit that completed latch without a quiet
probe. This includes a concurrent duplicate of the winning request id; only a replay that arrives
after the first attempt has completed takes the sanctioned repair path (issue #476).
The same in-flight gate covers a previously live client that then fails its handshake or
reconnects after an availability `ControlError`, so that path also produces one on-demand attempt.
Every later call under a *different* request id — any tool, any delegate sharing the MCP process —
is answered from that latch: same public code, same `correlation_id`, same `retryable`, the same
`safe_details` plus
`availability_inherited: true` and `availability_request_id` (the original id), and a message
suffix stating that no new diagnostic was recorded; no spawn, supersede, or diagnostic occurs.
Three continuations clear the latch: the original request id replays (the sanctioned repair-then-
retry path — success clears, failure re-latches with the new result); the stamped service holder
changes (`finishup service run|restart|stop` happened); or, for a retryable class only, one quiet
handshake (`connect_service`, never on-demand start or supersede) succeeds, in which case that
connection becomes the bridge's client. Per-request failures (`vault_locked`, policy, validation,
timeouts, draining) never latch. The latch is process-local: a fresh host launch probes once.

`response_projection_failed` is reserved for the window after a handler returns
for non-`publish_work` writes (and the impossible minimal-envelope path), where a write may already
be durable and only the response could not be shaped; it is always `retryable=True`, and the bridge
answers it with one same-`request_id` replay and then `status view=operation`. For
`publish_work` that same window returns the reduced total-acceptance success envelope instead of a
`ControlError`. Deliberate bounded failures raised in that window —
`privacy_projection_blocked`, `privacy_projection_unavailable`, and any `PublicOperationError` —
already state something true and pass through unchanged. An accepted durable publish must never
surface as a failure (`INTERNAL_ERROR` or otherwise).

Unexpected exceptions recorded in that window (and at other process boundaries) emit the existing
stderr structural line and also append one owner-only JSONL diagnostic record under `log_dir()`
(`service.diagnostics.jsonl`, mode `0o600`, size-capped ring). Fields are limited to
`timestamp`, `correlation_id`, `component`, `operation`, `reason`, optional `phase`, optional `origin`, optional
`request_id`, and the optional bounded integer counts `duration_ms` and `operation_count` — no
exception text, payload, or paths. A transient status read records `phase` as `handler`, `projection`,
or `unknown`; repeated polls on the same validated `(session_id, writer_id, view, task_id)` binding
reuse one incident correlation. A later successful fresh read emits one
`status_read_projection_recovered` record with the incident's phase, elapsed `duration_ms`, and
failure `operation_count`, then clears the process-local incident. A changed or superseded binding
cannot close that incident. The daemon's control-plane watchdog samples event-loop lag from a plain OS thread and
appends `control_plane_saturation_entered`/`_persists`/`_cleared` records (component
`service.daemon`) with those counts at a bounded cadence, so a starved control plane is diagnosed
while it is happening rather than never (#238); sweep failures append
`observation_sweep_failed`. A sweep-raised exception uses the unexpected-exception recorder so
its bounded reason and origin survive; only an actual sweep deadline records
`sweep_deadline_exceeded`. The same `correlation_id` is attached to the raised
`ControlError` (and to the reduced publish acceptance envelope when that path is taken) so the
agent-facing public error and the durable sink share one identity. The MCP bridge reuses a
service-supplied id rather than minting a second one; only bridge-local failures without a
service-side id mint and record under a fresh id. `finishup service diagnostics --correlation-id
err_…` reads that ring.

Every `correlation_id` minted through a boundary recorder is resolvable, not only the ones behind
an unexpected exception. Deterministic public failures — `INVALID_REQUEST`, `OPERATION_PENDING`,
`VAULT_LOCKED`, and any workflow `PublicOperationError` framed as an `ok:false` body — never raise
past a boundary recorder, so the boundary that mints their id writes the same ring record for it
at mint time. Minting and recording are one step in `record_public_error_without_raising`: the
ring record keeps the fixed field set above with `reason` the lowercased public code and
`operation` a bounded operation-context token derived from the failing method or tool
(`<method>_public_error`, collapsing to `public_error` when the name is not a bounded token);
`outcome: public_error` appears on the stderr structural line, which carries no more than the ring
does. A classified application exception that already recorded through
`record_classified_exception_without_raising` (bounded exception-class `reason` plus optional
`finishup` origin) is the same contract: the daemon reuses that id instead of minting a second
`public_error` or collapsing to `internal_error`. A boundary holding an id another sink already
recorded reuses it instead: one failure resolves to one id. The one path outside this contract is
the constructor-free last-resort
internal-error fallback (`build_last_resort_internal_error_result` in `mcp/errors.py`), which
exists for when building a normal public error has itself failed and returns a process-constant id
that resolves to nothing.

`PublishResponseCatalogPort` is the publish-only durable control-boundary response store. Its key
is `(task_id, session_id, writer_id, request_id, request_digest, sink)`, where `sink` is exactly
`agent_context|local_human_view`; the authoritative publish handler has already matched the
operation digest before the daemon consults it. A stored value is the exact canonical validated
`PublishWorkResult` body and its SHA-256 digest. Accepted-event `summary` is forbidden in this
structural store. Concurrent projections use atomic put-if-absent and return one durable winner;
the daemon rebuilds `rpc_id`, service instance, and service generation in the outer control result.
This stored-body guarantee applies only to `publish_work`; `start|check|respond|receipt` retain
their existing durable internal-result replay and still run client projection on each call.

`read_projection_failed` covers the same window for methods that append nothing
(`_READ_ONLY_METHODS` in `service/daemon.py`: `status`, repository privacy reads, and privacy
receipt reads). It is
also always `retryable=True`, but its remedy is a fresh request: advertising same-`request_id`
replay for a read points the caller at an operation record that was never written. Repository
setup/effective reads can also reach this reclassification because they traverse
ordinary local projection. `check` and `receipt` append their own events and are therefore writes,
not reads.

Inside that window the projection internals fail with bounded, named errors rather than bare
`KeyError`/`IndexError`: `_replace_pointer` raises `projection_pointer_unresolved` for an omission
pointer absent from the body and `projection_pointer_invalid` for a malformed one. These are not
remapped to `privacy_projection_blocked` — no policy blocked them, and that reason is
non-retryable, so it would describe an already-durable append as a refusal. They reach the daemon
and are reclassified by method. Either way the projection stops before a response exists, so
blocked content is never disclosed.

`ports/privacy.py` owns the shared receipt-inspection values `PrivacyReceiptAudience`,
`PrivacyReceiptQuery`, `PrivacyReceiptPage` (positive snapshot generation, bounded unique
descending receipt tuple, and optional schema-bounded base64url authenticated next cursor), and the
closed tagged union `PrivacyReceiptView = NetworkEgressReceiptView(kind="network_egress",
receipt=EgressReceipt) | LocalDisclosureReceiptView(kind="local_disclosure",
receipt=LocalDisclosureReceipt)`. Internal completion methods continue to accept raw receipt types;
`get_receipt` and `list_receipts` return only tagged wrappers.
The ordinary-control boundary models `ListPrivacyReceiptsRequest` and
`GetPrivacyReceiptRequest` exactly from the corresponding closed control-request bodies;
`service/client.py` owns schema-derived `PrivacyReceiptGetResult = found(PrivacyReceiptView) |
not_found`. The daemon alone maps the internal `PrivacyReceiptView | None` query result to that
wire union. No nullable result, port-method alias, plaintext, or object-dereference handle crosses
the control boundary.

`ServiceLifecycle` owns the one per-user instance and the exact
`starting -> locked|ready|failed`, `locked -> unlocking|recovering|draining|failed`,
`unlocking -> ready|locked|failed`, `recovering -> ready|locked|failed`, `ready -> draining|failed`,
`draining -> locked|failed|final close`, and `failed -> draining|final close` transitions. “Final
close” is terminal process teardown, not a serializable `ServiceState`. Only a ready
service constructs `Application`, `BundleRuntimePort`, storage/key/provider adapters, the privacy
coordinator, and the outbound gateway. A service lock/suspend/session-lock transition first stops
admission, resolves bounded shielded commits, closes provider/runtime handles, invalidates vault
generations, then reports `locked`. Resume never implies ready.

`ServiceLifecycle.change_idle_relock_policy(proposed, proof)` is the only idle-policy mutation
path. `IdleRelockPolicy` defaults to 3600 seconds, accepts finite `60..86400`, and may use its
internal `seconds=None` disabled state only after this method atomically consumes the exact
vault-minted proof. The exception is scoped to the current service generation, is not persisted,
and restart restores 3600 seconds. Explicit, session-lock, suspend, and monitor-loss relock remain
enabled when idle relock is disabled.

Shared lifecycle/control values are `ServiceInstance`, `Admission`, `SessionSecurityEvent`
(`user_session_locked|system_suspend|user_session_unlocked|system_resume|monitor_lost`),
`IdleRelockPolicy`, `LifecycleError`, `ControlSession`, and `ControlProtocolError`. Shared vault
values are `VaultMode` (`uninitialized|os_keyring|passphrase`), `VaultState`
(`locked|unlocking|ready|closing|closed`), `VaultStatus`, `ProviderCredentialBinding`, and
`VaultError`. Client-visible status never contains a PID, path, username, key locator, provider
credential presence, user content, or timing history.
Ordinary `ServiceStatus` remains schema 1.0.0 and carries no artifact fact. The dedicated trusted
`finishup service recovery status` projection returns `InstallationRecoveryStatus` with
`recovery_state` exactly
`pristine_setup|temporarily_locked|auto_unlock_repairable|recovery_material_required|
recovery_in_progress|recovered|permanently_unrecoverable`. A continuation contains only an opaque
operation id and exact constant trusted command. It contains no path, artifact/secret fact,
keyring identity, or user content. Ordinary CLI/MCP locked errors point agents at that exact status
command and never accept a recovery secret or set path.
`ServiceStatus.state_reason` is the closed registry `none`,
`auto_unlock_backend_unavailable`, `auto_unlock_rejected`, `auto_unlock_stale`, `keyring_locked`,
`keyring_unavailable`, `passphrase_required`, `human_authority_unavailable`,
`vault_uninitialized`, `unlock_failed`, `explicit_lock`, `idle_relock`, `user_session_locked`,
`system_suspend`, `monitor_lost`, `recovery_material_required`, `recovery_in_progress`,
`recovery_failed`, `permanently_unrecoverable`, `shutdown_requested`, or `internal_error`. `keyring_locked`
applies only to `vault_mode=os_keyring`.
Passphrase startup with no scoped entry reports `passphrase_required`; a validly encoded entry that
does not authenticate the current envelope reports `auto_unlock_stale`; structural platform access
or entry failures use the two other `auto_unlock_*` reasons. None reveals entry bytes, paths, or
credential/policy state.
After a soft lock (`idle_relock`, `user_session_locked`, `system_suspend`), the
service may re-read the same scoped entry (or retry OS keyring) before denying ordinary
control with `vault_locked`. When the credential succeeds but ready-application activation fails,
the service preserves the soft-lock reason for up to three consecutive attempts so a later dispatch
can retry; a fourth consecutive activation failure becomes terminal `unlock_failed`.
The resulting `VAULT_LOCKED` error is retryable only while this automatic recovery path remains
eligible. `explicit_lock`, `monitor_lost`, and hard `auto_unlock_*` /
`passphrase_required` reasons do not take that path. The trusted unlock helper may submit the scoped entry through the
confidential unlock ceremony without a TTY prompt when the entry is present.
`ServiceStatus.state_reason=human_authority_unavailable` has exactly two valid combinations:
`state=locked,vault_mode=uninitialized` when pristine setup was blocked before keyring mutation,
rendered as setup required; and `state=ready,vault_mode=os_keyring` for an existing vault whose
local workflows are admitted but external-provider capability is absent. Neither combination
reveals credential or policy state.

A never-initialized vault is not a dead end for the start-first agent flow (issue #512). When a
workflow call fails with non-retryable `vault_locked`, the MCP bridge performs one bounded
fresh-handshake probe — the hello-result already carries the structural `ServiceStatus`, the one
surface an ordinary bridge peer is allowed — and, only when that snapshot proves
`state=locked,vault_mode=uninitialized`, attaches the typed `vault_initialization_required`
continuation to the public `VAULT_LOCKED` error (`safe_details` keys under the public-error
section). The continuation is a bounded handoff, not a retry license: the caller follows the
carried prepare command into the ordinary ADR-015 consent ceremony (the prepared pending carries
the exact danger text, danger digest, target digest, expiry, and decision commands the user's
decision binds to), and after the ceremony reports a terminal result replays the exact original
`request_id` and body once — idempotent by construction, because the failed call reserved
nothing. Denial, expiry, unavailable user presence, unsupported keyring, an existing credential,
ambiguous initialization, and service replacement keep their distinct bounded outcomes from the
consent and staged-credential contracts. A probe failure, any other vault state, and every
initialized-vault lock keep the existing unlock/recovery answer unchanged; the Cursor host
profile omits `authorize_command`, since that binding is never an agent-chat attestation client.

`AutoUnlockPassphraseStore` is a trusted-service/setup adapter, not an ordinary control port. Its
credential-store service name is `yoetz.auto-unlock.v1`; its account identity is
`bundle-<sha256(os.fsencode(abspath(bundle_root)))>` for the active slot, with sibling
`-staged-rotation` and `-staged-initialization` accounts for the two staged slots. It accepts only
exact vault-passphrase bytes, base64url-encodes them for the allowlisted platform backend, verifies
writes by round trip, and returns only bounded structural load reasons. Setup, boot, and
trusted-TTY repair overwrite mutable buffers best-effort. Setup and repair resolve the bundle
through the same effective configuration and environment inputs as daemon startup. Setup falls back
to a human-chosen passphrase only for a platform-store failure guaranteed to occur before any
write. If a write may have committed but cannot be read back exactly, setup stops before vault
initialization and requires recovery of platform-store access; it never initializes a different
manual secret beside the ambiguous entry. Generated initialization (issue #511) stages its fresh
secret in the staged-initialization slot, never the active entry, and promotes it only after the
validated ready result; restart unlock tries active then staged candidates and promotes or
discards each strictly by proof against the vault envelope. No MCP method, ordinary control body,
config value, environment value, argv value, stdin path, or log field can carry the secret.
Active-slot deletion is not exposed until it can be atomically coupled to a human-known passphrase
rewrap; a staged slot is deleted, with verified read-back, only after proof that no vault envelope
depends on it (the accepting unlock disproved it, or the live service reports a locked,
uninitialized vault). CLI-side staging, promotion, and proof-based discard serialize on a
bundle-scoped advisory lock held by the initializing process for its whole
stage→ceremony→promote span and re-checked by discard-only callers while held, so a stale status
read can never delete a credential whose vault commit is in flight, and generated-passphrase
installations cannot be stranded. Because trusted initialization may run before any service start
has created the bundle root (issue #565), the guard first creates exactly that root, owner-only and
only when its parent already exists, then verifies the path symlink-free, owned, and owner-only with
the same helper the service uses; it never creates anything outside the selected bundle. Guard
filesystem failures keep distinct bounded reasons — `bundle_parent_missing`,
`bundle_permission_denied`, `bundle_unsafe`, `guard_unavailable` — and `unsupported` is reserved
for a platform that genuinely lacks the mechanism, so only that reason may take setup's
human-chosen-passphrase fallback.

`SecretMemoryPort` exposes `capability`, `capture`, `allocate`, and `close` over opaque one-shot
`SecretHandle` values. `SecretPurpose` is exactly `vault_initialize`, `vault_unlock`,
`vault_root_key`, `portable_recovery`, `installation_recovery`, `vault_rewrap`, `object_payload`,
`provider_reauthentication`, `provider_credential`, `privacy_reauthentication`, or
`security_reauthentication`; `SecretConsumer` is exactly `vault_root`, `recovery_wrapper`,
`installation_recovery`, `vault_rewrapper`, `object_crypto`, `provider_authorizer`,
`privacy_authorizer`, or `security_authorizer`. Shared types are
`SecretMemoryCapability`, `ProviderAttemptAuthBinding`, `ProviderAuthTransportCallback`,
`ProviderCredentialHandle`, `HumanAuthorizationProof`, `UserPresenceChallenge`,
`UserPresenceAttestation`, `UserPresenceCapability`, `UserPresencePort`, and
`UserPresenceError` (closed reasons `unavailable`, `cancelled`, `failed`, `timeout`; no OS text),
plus the pure `presence_confirmation_code(target_digest)` (the first eight hex digits of a SHA-256
target digest as `xxxx-xxxx`). Strong OS presence is
exact action/generation-bound and capability-tested; TTY/same-UID/unlocked-session booleans are not
implementations. Buffers are
bounded mutable allocations with measured page-lock/no-core capability and best-effort overwrite;
the contract explicitly makes no CPython zero-copy or perfect-zeroization claim.

`HumanAuthorizationProof` has exactly `proof_id`, `purpose`, `target_digest`,
`service_generation`, `vault_generation`, `policy_generation: int | None`,
`issued_at_monotonic: float`, and `expires_at_monotonic: float`. Its sole additional member is the
private `_consume_latch` with `init=False`, `repr=False`, `compare=False`, excluded from
copy/pickle/serialization. Internal
`consume(expected_purpose, expected_target_digest, service_generation, vault_generation,
policy_generation, now_monotonic) -> None` validates every binding/expiry and atomically flips that
latch. The proof is internal and never serialized. `UserPresencePort.consume` validates and
invalidates an exact attestation/challenge and returns `None`; it cannot construct or return
authority. `VaultService.mint_human_authorization` is the sole proof constructor for both a
consumed exact OS-presence source and an admitted purpose-specific passphrase reauthentication
source; any failure of `UserPresencePort.consume` (foreign, replayed, mismatched or stale
attestation) becomes `VaultError("human_authority_unavailable")` and mints nothing.

The one production `UserPresencePort` is `MacOSLocalAuthenticationPresence`
(`adapters/keys/macos_user_presence.py`, issue #1073). `select_service_user_presence(platform)`
returns it for `darwin` and `None` for every other platform; the packaged daemon passes the same
instance to `VaultService(user_presence_port=...)` and to
`HumanControlService(user_presence=..., user_presence_scope=PresenceScope(purposes, vault_modes))`
with `OWNER_VIEW_PRESENCE_PURPOSES = {"owner_receipt_view"}` and
`OWNER_VIEW_PRESENCE_VAULT_MODES = {"os_keyring", "passphrase"}`. Outside its scope human control
neither offers nor accepts `os_user_presence`, and keyring retry receives no capability. Its
`assert_presence` runs `run_presence_helper(("/usr/bin/osascript", "-l", "JavaScript", "-",
reason), program, {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}, 75.0)` (no shell, `cwd="/"`,
killed and reaped on deadline or cancellation); `reason` is fixed per purpose apart
from the confirmation code. The helper's single stdout token (`approved`, `cancelled`, `failed`,
`unavailable`, `timeout`, optionally newline-terminated, exit status 0) is parsed exactly; anything
else is `unavailable`. `approved` yields an opaque, unpicklable attestation bound to the exact
`UserPresenceChallenge`, consumed once within 30 seconds. Its `UserPresenceCapability` names
`adapter_id="finishup.presence.macos-local-authentication"` (the FinishUP spelling: new in 0.3 and
never stored, released or carried by a schema, ADR-048 §1),
`profile_id="device-owner-authentication/1"`, `release_cell="unqualified"`, and the helper digest
as both evidence digests, so it never satisfies a runtime-support `user_presence_cells` row. `UnlockCoordinator` exclusively owns the durable passphrase throttle and calls the vault
only after admission/reservation; `unlock_rate_limited` is therefore a coordinator outcome and not
a `VaultError`.
Every vault-opening completion additionally calls one injected async daemon activation callback
with the exact current service and vault generations while lifecycle state remains `unlocking`.
That callback builds and validates a fresh Application, atomically installs it, and transitions the
lifecycle to `ready`; it returns only after daemon ownership transfers. Failure closes partial
ready state in reverse order, relocks the vault/lifecycle, and returns the bounded
`unlock_failed` structural reason. Unlock success is impossible without this callback succeeding.
Before first passphrase publication, `UnlockThrottleStore.stage_or_adopt_initial_record()` may
adopt without rewrite only the exact valid generation-1, zero-failure, inactive record for the
same installation. This is the sole clean-crash continuation for a provisional throttle record;
all advanced, active, mismatched, unsafe, or malformed records fail closed and are never reset.

Provider mutation uses only
`VaultService.store_provider_credential(action, binding, secret, proof, now_monotonic)`. The
action is exact `set|rotate`; the secret is one `provider_credential` handle; and the proof purpose
is the matching `provider_credential_set|provider_credential_rotate`, bound to the same target and
service/vault generations with no policy generation. The vault consumes the proof in the same
non-interleavable mutation section as its record-generation CAS. Human control cannot exchange a
proof for a weaker reusable binding, and no credential record can commit without that exact proof.
After a successful store, human control may dispatch one minimal `credential-probe` request only
when the effective `llm_inference` policy explicitly lists that purpose. Provider setup asks for
that separate authorization, and the resulting policy preview and widening decision show the exact
allowed-purpose set; enabling external review alone never adds the probe. The probe carries only
the fixed structural literal and traverses the same authorization, one-attempt credential
transport, and durable egress-receipt path as inference. Only a provider refusal of the credential
(HTTP 401/403) withdraws the record via `VaultService.discard_provider_credential(binding)` and
fails the ceremony as `secret_rejected`; a rate limit counts as accepted, and timeout, transport
failure, outage, or unsupported-profile answers leave the stored credential in place as
unverified.

Pristine automatic keyring initialization requires both an approved create-if-absent/round-trip
keyring probe and an installed `UserPresenceCapability` matching an active
`user_presence_cells` row in the verified packaged runtime-support manifest for the same artifact,
release cell, and evidence digest. Its `available`, `os_authenticated_prompt`,
`trusted_action_binding`, and `one_use_attestation` states are all active. The keyring adapter then
mints a one-attempt opaque `FirstInstallKeyringAuthority` bound to service generation,
pristine-state digest, and both evidence digests; `create_and_verify` requires it. Failure creates
no stage, IVK, entry, or marker and returns `human_authority_unavailable`. This is not a live
`UserPresenceAttestation`, and no caller-supplied capability or boolean is accepted.

`ProviderCredentialBinding` freezes exact provider/model/endpoint profile ID+version, the exact
bounded lower-kebab purpose token, authorization-scope digest, and purpose digest. The purpose
digest is exactly `canonical_digest({"purpose": purpose})`; a mismatching pair is invalid before
storage or handle minting. `ProviderAttemptAuthBinding` freezes those same fields plus dispatch ID,
final request-body SHA-256 digest, service
generation, and deadline. Minting a credential handle requires every shared field to match the
stored credential binding; a scoped credential cannot authorize another model, scope, or purpose.
`VaultService.has_provider_credential(binding)` reads only the exact structural record-generation
index and returns presence; it neither decrypts the record nor creates a credential handle.
`ProviderCredentialHandle.authorize_attempt(binding, inject_and_start)` is single-use: after exact
binding/body/deadline validation it exposes a protected view only inside the injected custom HTTP
transport callback for authentication-header injection and one request start, then releases it
immediately. Retry requires a new dispatch-bound handle. Provider SDK clients/default headers never
receive or retain the real credential; HTTP/TLS internals may copy header bytes, so no perfect
zero-copy claim is made.

Pure `service/confidential_protocol.py` owns both closed client-safe wire contracts. YZH1 is the
multi-phase structural channel with `HUMAN_PROTOCOL_MAGIC`, version/cap, exact eleven
`HumanCeremonyKind` values, `HumanOpenTarget`/`HumanPreview`/`HumanAction`/`HumanPhase`/
`HumanResult` unions, ceremony/decision bindings, eight correlated envelope types, bounded errors,
and terminal close. YZS1 is the one-secret binary channel with `SECRET_PROTOCOL_MAGIC`, version/
caps, `ConfidentialSecretPurpose` wire codes, and `SecretIngressBinding`. Shared byte policy is
16..1,024 strict UTF-8/no NUL-CR-LF/no normalization for passphrase purposes and a generic
1..8,192/no NUL-CR-LF provider-credential transport cap followed by the exact installed profile
validator.

`HumanPhase` is exactly `secret_required|authorization_required|keyring_retry|decision_required`.
Every serialized YZH1 ceremony/decision binding and YZS1 `SecretIngressBinding` carries
`expires_at_monotonic_ms`, a nonnegative canonical JSON safe integer. The service captures
`ClockPort.monotonic_seconds()` once, computes issue milliseconds as
`floor(monotonic_seconds * 1000)`, rejects a nonfinite/negative/overflowing input, and adds exactly
`CEREMONY_EXPIRY_SECONDS * 1000`; no float is serialized. Expiry comparison converts the current
monotonic sample with the same floor rule.

`HumanCeremonyKind` is exactly `vault_initialize`, `vault_passphrase_rotate`, `vault_unlock`, `keyring_retry`,
`portable_recovery`, `installation_recovery`, `provider_credential_set`, `provider_credential_rotate`,
`privacy_policy_decision`, `privacy_disclosure_decision`, `idle_relock_policy_change`, and
`owner_receipt_view`. `owner_receipt_view` opens directly at `AuthorizationRequiredPhase`
(`privacy_reauthentication` purpose); on success its effect consumes the proof for the target
digest and returns `OwnerReceiptViewResult(status="authorized", target_digest, grant_seconds=60)`.
Its `available_sources` are `os_user_presence` when the composed presence provider is in scope and
available (macOS), then `secret_reauthentication` in passphrase mode. Selecting
`os_user_presence` starts the provider in the service; the human-control mutex is released while
the dialog waits, a second action on that ceremony is `phase_invalid`, and `cancel`, `close` or a
human-control peer that closes or cancels during the wait ends the dialog. The bounded YZH1 server
error codes add `presence_refused` (cancelled, or the OS did not authenticate the person) and
`presence_timeout` (no answer before the dialog deadline) beside `presence_unavailable`, plus
`ceremony_busy` (another ceremony is active; this was `state_forbidden` before #1073) and
`reauthentication_rate_limited` (a throttled passphrase, also `state_forbidden` before, or the
presence backoff `PRESENCE_BACKOFF_SECONDS = (5, 15, 30, 60, 120, 300)` seconds per consecutive
prompt that did not approve: refused, timed out, or cancelled after at least
`PRESENCE_MIN_SHOWN_SECONDS = 2`; reset by an approval or by `PRESENCE_MISS_DECAY_SECONDS = 600`
without a miss; a prompt cancelled sooner does not escalate, but the next one still waits the first
step, so after any prompt that did not approve the helper starts again no sooner than 5 seconds
later; held in service memory, so a restart clears it). An active ceremony past its
binding expiry is ended by the next `open_ceremony` instead of answering `ceremony_busy`. The
confidential client passes all five through to its caller; their local recovery directives are
`ceremony_in_progress` (approve, cancel or restart nothing; report that a confirmation is already
open and let the owner decide) for `ceremony_busy` and `ceremony_retry_after_wait` (wait up
to five minutes, retry once) for `reauthentication_rate_limited`. A client
cancel frame that arrives while a presence prompt is up is answered with a `cancelled` error
correlated to that frame, then the close. On the CLI, `finishup receipt --owner-view
[--use-passphrase]` runs the ceremony through `cli.unlock.authorize_owner_receipt_view(target, *,
use_passphrase)`; on macOS it first prints `owner_view_confirmation_code(target)`. Without
`--use-passphrase` it never prompts for a passphrase that
`vault_passphrase_held_by_credential_store()` reports as possibly held (the installation's
auto-unlock slot is present, refused, or unreadable; only `auto_unlock_absent` or a platform with
no approved credential store allows the prompt) and fails with the CLI reason
`passphrase_in_credential_store`; `--use-passphrase` on a
vault that offers no passphrase fails with `passphrase_unavailable`. Both CLI reasons render as
`owner_view_unavailable`, and `ceremony_busy` renders as `owner_view_busy` with this command's
code. `reauthentication_rate_limited` after the command selected `secret_reauthentication`
(`--use-passphrase`, the fallback after an unavailable dialog, or Linux and WSL 2) is the durable
passphrase throttle and becomes the CLI reason `passphrase_rate_limited` (`owner_view_refused`,
no restart or `--use-passphrase` hint, since a restart does not clear it); after
`os_user_presence` it stays `reauthentication_rate_limited` and names both. The terminal
interface's *Your full receipt* maps the same two cases the same way.
`CEREMONY_EXPIRY_SECONDS = 300` is the one YZH1/YZS1 challenge/binding expiry. It bounds a whole
human ceremony, including the trip to a provider console to mint an API key, so it is a five-minute
span rather than a keystroke timeout. While a `SecretRequiredPhase` is live, the human-control
handler waits for YZS1 **or** a close/cancel on the YZH1 peer. Killing the foreground ceremony
client (EOF at the passphrase prompt) cancels the one global ceremony immediately. `service stop`
must not wait on that mutex: `secret_completed` releases it while waiting, `close()` cancels any
still-active ceremony, and `UnlockCoordinator.cancel` returns UNLOCKING to LOCKED without reversing
an in-flight DRAINING/FAILED transition. Shutdown that cancels a live ceremony records
`ceremony_shutdown` / `cancelled` in the owner-only diagnostic ring. The nine fixed
`ConfidentialSecretPurpose` wire codes are `1=vault_initialize`, `2=vault_unlock`,
`3=portable_recovery`, `4=provider_reauthentication`, `5=provider_credential`,
`6=privacy_reauthentication`, `7=security_reauthentication`,
`8=installation_recovery`, and `9=vault_rewrap`.

`PrivacyPolicyDecisionPreview` is exactly `{kind, pending_id, diff_digest, changes, members}`.
For a single-layer transition, `changes` is the complete substantive policy diff as closed
`PrivacyPolicyChange` records —
`{area, field, subject, before, after, widens}` — never a summary of it and never explanatory
prose. `area` is one of `global|review|channel|local_model|agent_context|human_control`; `field`
is an allowlisted token belonging to that area (`PRIVACY_CHANGE_FIELDS`); `subject` is the
channel identifier for `channel` and null everywhere else. `before`/`after` are bounded canonical
values tagged `none|flag|count|labels`, where `none` means "does not apply on this side" and is
distinct from `labels: []` meaning "applies and permits nothing"; labels are sorted, deduplicated,
at most 64, and match `^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,127}$` so nothing written to `/dev/tty`
can move a cursor. `widens` is server-derived, never client-supplied.

The invariant: the service derives `changes` and the tightening classification from the one
`privacy_policy_changes(current, candidate)` comparison, so `is_privacy_tightening` is exactly
"no returned change has `widens=true`". A dimension the classifier treats as widening therefore
cannot be absent from the screen a human approves it on. The set is deduplicated by
`(area, field, subject)`, sorted widenings-first by fixed impact rank, capped at 128 changes and
32 KiB encoded, and a `privacy_policy_decision` preview whose change set contains no widening is
rejected rather than rendered. Simultaneous tightenings are included so the human sees the whole
diff. For a compound transition, top-level `changes` is empty and `members` is the complete ordered
set of `PrivacyPolicyTransitionPreviewMember(authority, action, changes)` values. `authority` is
`machine_ceiling|repository_grant`; `action` is `replace|insert`, subject to the closed valid
combinations enforced by that type. A first repository grant may contain both a machine-ceiling
replacement and repository-row insertion; those members are rendered together and commit
atomically. The `PolicyTransitionProposal.authority_digest`, rather than an extra confidential
preview field, binds that decision to the machine ceiling, repository commitment and current row,
ancestors, migration frontier, and applicable bounded entitlement. Neither member can become
effective alone. Lineage-only fields (`policy_id`, `version`, `policy_digest`, `created_at`,
`supersedes_policy_digest`) are excluded because they always differ on a fresh candidate and
describe no disclosure boundary. `diff_digest` remains integrity evidence binding the decision to
exact bytes; it is not the human-readable description, and the trusted renderer says so. Fixed
plain-English labels for every `(area, field)` live in `cli/unlock.py`, not on the wire.

`HumanOpenTarget` has exactly five branches: `EmptyVaultTarget`, `PortableRecoveryTarget`,
`ProviderCredentialTarget`, `PrivacyPendingTarget`, and `IdleRelockPolicyTarget`. The last is
exactly `{kind:"idle_relock_policy", operation:"set", seconds:60..86400}` or
`{kind:"idle_relock_policy", operation:"disable"}`; no null/infinity/string alias exists. The
ninth `HumanPreview` branch carries tagged current/proposed finite-or-disabled values, service
generation, and the canonical target digest. The sixth `HumanResult` branch carries previous and
effective tagged values, `scope:"service_generation"`, and service generation. Policy expansion
and idle-policy change accept `approve|deny`, then require
`select_authorization_source=os_user_presence|secret_reauthentication` before mutation; there is
no server-side `edit` action. Idle-policy secret reauthentication uses only wire purpose 7 and
`SecretPurpose.security_reauthentication`/`SecretConsumer.security_authorizer`.

`SecretIngressService` and `HumanControlService` are server authority. Client-safe
`service/confidential_client.py` alone exports `HumanControlClient`, `HumanControlSession`, and
`ConfidentialSecretClient`; it imports only the pure protocol and connect-only local transport.
`cli/trusted_console.py` owns the `TrustedForegroundConsole` boundary and `cli/unlock.py` owns the
confidential ceremony driver. On macOS/Linux the console opens `/dev/tty`, matches the standard
input/error terminal identity, verifies the foreground process group, disables raw secret echo,
and writes one `*` mask marker per accepted input unit. On Windows it opens
`CONIN$`/`CONOUT$`, validates real console handles and current-process attachment, disables raw
secret echo, and writes the same mask feedback through Win32 console APIs. Backspace removes one
marker. The mask intentionally reveals entered length to a local terminal observer, never content.
It never falls back to
redirected standard streams. These channels are absent from
`ControlClientPort`, ordinary CLI/MCP import graphs and schemas, argv, environment, config, stdin,
logs, traces, transcripts, and LLM context. These console properties protect secret ingress but
never establish human presence; pseudo-terminal and same-UID automation are explicitly rejected as
authorization signals.

Elevated consent (`service/elevated_bootstrap.py`, CLI `finishup consent` /
`finishup elevated-bootstrap`) is a separate owner-only pending-file lane outside
`ControlClientPort`. It catalogues non-default operations (`yoetz.consent.catalog/6`) and creates
digest-bound pending records (`yoetz.elevated-bootstrap.pending/4`). The agent-safe projection
contains only operation, risk class, bounded danger text, exact digests, expiry, pending ID, an
exact bounded repository recipe when applicable, the fixed `["finishup","consent","review"]`
command, and an authorize command only for operations that permit agent-chat authorization. A
repository grant additionally exposes `yoetz.repository-privacy-grant-preview/1`: exact recipe,
keyed repository commitment, authority/current/candidate/diff digests, and the complete bounded
substantive before/after policy diff. The owner-only pending record freezes both policy byte sets;
the readable diff is the decision surface and its digest is only integrity evidence. Legacy v1-v3
durable records are invalidated. Catalog rules explicitly state that agent attestation is
not independent proof and that a compromised agent can forge it.

`finishup consent review` remains the OS-presence console path. It requires an independently
authenticated, action-bound, one-use `UserPresencePort` attestation before opening the trusted
console or atomically claiming the request. Because no production adapter is wired, it returns
`human_authority_unavailable` and leaves pending state untouched. No TTY, pseudo-terminal, same-UID
process, argv, environment, stdin, MCP, JSON, or caller boolean can authorize console review.

`finishup consent authorize` is the delegated agent-chat path (issue #164). It accepts one
`yoetz.chat-user-attestation/1` envelope (`channel=agent_attested_chat_instruction`, allowlisted
`client_kind`, `instruction_source=explicit_current_chat_user`, exact
pending/operation/danger/target digests, decision, and `warning_acknowledged` for approve).
FinishUP treats the assertion as authority but cannot independently authenticate its chat provenance;
a compromised agent can forge it. Implemented agent-chat operations are `vault_initialize`,
`vault_passphrase_rotate`, `provider_credential_set`, `provider_credential_rotate`,
`repository_privacy_grant`, and the service-prepared `import_publication`.
Credential approve may read one secret from stdin (`--provider-credential-stdin`); results are
presence-only and never echo secret bytes. Vault initialization accepts no caller secret: the local
helper generates and scoped-credential-store-verifies it before confidential submission. This lane does not
unlock an already-locked vault. The six MCP tools (ADR-011) are unchanged; authorize is local
CLI control.

`expanded_review` is an admitted exact repository recipe on this lane. Prepare binds the frozen
candidate and diff to the repository commitment, authority generation, provider/model/endpoint,
recipe, policy digests, target, and expiry. Authorize rechecks repository identity, authority
snapshot, and the configured provider route, then proposes only the frozen candidate. Drift,
denial, expiry, replay, malformed preview, or unsupported client yields no policy/provider mutation.
Agents guide setup, installation, and settings changes in normal conversation, recommend with
trade-offs, and treat explicit current user intent as final for supported product choices. When the
user explicitly asks for AI-powered review depth, Expanded is recommended first and Assisted is
explained as the lower-disclosure AI-powered review option. Recommendations never override technical
authority, policy, never-send, credential, destructive-action, or evidence boundaries.

A consent action is recorded approved only after its operation result is validated as the exact
success the review-result schema admits (issue #510). A ceremony that ends in any other state —
for example a locked vault reporting `throttle_record_exists` — consumes the pending decision
with audit outcome `failed` and a bounded `failure_reason`, prints
`elevated_bootstrap: vault_result_<reason>` (`result_invalid` for a result outside the schema),
and leaves no durable claim of approval, so failed execution stays distinguishable from denial,
expiry, and completion. Retry is one new `finishup consent prepare`, which rebinds the identical
target digest for vault operations. A failed generated rotation never promotes the staged
scoped-credential replacement; startup reconciliation still owns the staged slot. A failed
generated initialization likewise never leaves the credential in the active slot (issue #511): the
same-attempt staged entry is removed with proof when the vault is still uninitialized, or retained
as a typed orphan that `finishup service auto-unlock status` distinguishes
(`initialization_orphaned`, `initialization_unreconciled`, `pre_existing_unadoptable`),
`finishup service auto-unlock repair` clears under the same proof, and restart reconciliation
resolves by proof, so retry never fails on `auto_unlock_entry_exists` from an abandoned
same-attempt entry.

`finishup service auto-unlock status` (`yoetz.auto-unlock-status/2`) also carries
`custody: platform_store | owner_file` (issue #1119, ADR-008 amendment 2026-10-19). `owner_file`
means the scoped secret lives in FinishUP's owner-only files under `<bundle>/auto-unlock/`, used
only where no platform credential store is usable. `finishup setup vault --passphrase` creates a
new vault from an owner-typed passphrase and keeps no copy; it refuses an initialized vault
with `vault_already_initialized`. A local-only first run creates the vault with no question
before its privacy step and stops with `vault_setup_incomplete: <reason>` when it cannot.

A `repository_privacy_grant` result is commit-aware (issue #519). The service records the
durable policy transition before it sends the correlated ceremony result, so when only the
trailing close confirmation is missing, wrong, or lost with the connection, the confidential
client carries the already-validated result instead of discarding it, and authorize recovers
that stored terminal outcome exactly once, read-only — a committed grant completes as `granted`
with a consumed approved review, and a carried denied or stale result stays a bounded failure
with no grant. The privacy expansion is never replayed as a new decision. When the decision was
submitted but no result is in hand and the transport outcome is unprovable, authorize reports
the typed `elevated_bootstrap: repository_privacy_grant_unconfirmed` instead of claiming
failure, and `finishup provider status` remains the authoritative read of the repository grant
state. A genuine pre-commit proposal or decision failure still reports
`repository_privacy_grant_failed` with no grant.

The current public JSON Schema contracts are `catalog`, `pending-agent`, `prepare-result`,
`review-result`, and `status`, each at version `7.0.0` under `schemas/consent/`; frozen versions
`2.0.0` through `6.0.0` remain shipped for compatibility. `consent prepare` and `consent status`
emit `pending-agent/7` for every operation, naming the launcher the command was invoked through
(`finishup`, or `yoetz` through the deprecated transitional alias; ADR-048); released `/6`
projections (head `yoetz`) and `/7` projections from a pre-rename service are still read. A pending
record written before the rename keeps its pre-rename danger text and stays valid (ADR-015
amendment). The current version report is
`version/version-manifest-2.0.0.schema.json`; its released `1.0.0` predecessor remains byte-frozen.
`yoetz.chat-user-attestation/1` is version 1.0.0.
`review_only` irreversible
operations remain catalogued with `implemented=false` until owning mutation paths consume review.
The Windows console adapter is a focused boundary implementation, not a claim that the FinishUP
service, transport, peer authentication, packaging, or release surface supports Windows.

`HumanControlService` implements trusted `HumanPrivacyControlPort`. Policy widening/provider
credential/admin changes require exact OS `UserPresencePort` or established passphrase-mode
reauthentication. A `confirm_every_request` prepared disclosure already within all durable policy
ceilings instead uses exact foreground digest-bound `/dev/tty` approve/deny with no strong reauth
and cannot widen policy. Keyring mode without measured presence has no passphrase fallback:
`HumanAuthorityCapability.source=unavailable` fences external activation/dispatch without rewriting
stored policy/credentials. No decision JSON, reusable token, proof, preview, or secret returns to
ordinary CLI/MCP/stdout.
This ready-local behavior applies only to already committed keyring mode. On pristine
uninitialized state, missing presence evidence blocks immutable keyring-mode creation. Explicit
manual passphrase initialization and exact agent-authorized helper-generated passphrase
initialization remain separate choices.

Passphrase rotation is the `vault_passphrase_rotate` ceremony over an
`EmptyVaultTarget(expected_mode=passphrase)`. It consumes a security-reauthentication secret and a
distinct `vault_rewrap` replacement, keeps the IVK and vault records unchanged, and atomically
replaces only the authenticated envelope. Manual rotation stages the user-selected replacement;
agent-authorized rotation stages a locally generated replacement. Startup reconciliation tries
the active and staged scoped credential entries and retains only the candidate that authenticates
the committed envelope.

### Several-agent setup batches (issue #1119)

`cli.host_batch` composes the existing host connection plans for CLI and full-screen first run.
`HostConnectionBatchReport` is the additive `yoetz.host-connection-batch-report/1` contract
(`integrations/host-connection-batch-1.0.0.schema.json`); it carries individual
`HostConnectionBatchMember` outcomes (`preview|completed|unchanged|status|incomplete|not_attempted`)
and preserves `connection_observed=false`. The released single-host contract is unchanged.
`batch_digest` hashes canonical JSON for the sorted list of `{host, installation_path,
request_id, preview_digest}` objects, ordered by those four fields. `prepare_batch` and
`apply_batch` retain each exact per-host digest; every member is refreshed before the first write
and per-host apply still revalidates under its configuration lock. There is no batch atomicity
claim: a failed later host leaves earlier results intact and the remainder requires a fresh
preview. `batch_command` pins repeated host/path/config-root selections plus project and explicit
route; the hidden `--batch` flag preserves combined acceptance when only one target remains.
`select_batch_installation` retains Codex's discovered, PATH-visible executable name during
explicit replay (`select_installation(preserve_visible_name=True)`), including a symlinked
launcher. Ordinary single-host selection keeps its released resolution behavior.
The batch request identity is shared across independent per-host plans. `--host all` expands
executable-backed discovery; it cannot discover configurations whose executable has been removed.
`setup status --next` retains its single-target readiness contract. No new MCP or hook operation
or receipt field is introduced.

### Privacy policy, disclosure, and outbound gateway

The closed privacy enums are:

- `PrivacyProfile`: `local_only`, `confirm_every_request`, `minimal_external`,
  `trusted_provider`;
- `ReviewContextProfile`: `structural`, `goal_aware`, `assisted`, `expanded`, `custom`; it is
  orthogonal to `PrivacyProfile` and controls deterministic AI-powered review case selection only;
- `EgressChannel`: exactly `llm_inference`, `product_telemetry`, `crash_diagnostics`,
  `update_checks`, `capability_testing`;
- `LocalDisclosureSink`: `local_model`, `agent_context`, `local_human_view`,
  `trusted_human_control`. `agent_context` is an agent-capable host's model context, which the host
  may forward to its own provider. `local_human_view` is the owner's own view of a vault they
  already unlocked; it is not a disclosure to a third party and is not gated by the agent ceiling.
  Selection is server-side and fail-safe: every ordinary client result resolves to `agent_context`,
  whatever its rendering, terminal or client kind (a pseudo-terminal passes every terminal test),
  and only a `cli`/`ui` receipt call for which the daemon consumed a reauthenticated one-use
  `owner_receipt_view` grant resolves to `local_human_view` (ADR-009 round 3);
- `DataClass`: `public_structural`, `ordinary_user_content`, `sensitive_confidential`,
  `secret_or_cryptographic`;
- `DataCategory` (owned by `protocol/models.py`, imported and re-exported by
  `domain/privacy.py`): `bounded_structural_metadata`, `declared_file_type`, `task_description`,
  `claim_text`, `obligation_text`, `decision_excerpt`, `evidence_excerpt`, `finding_summary`,
  `command_metadata`, `diff_metadata`, `repository_excerpt`, `transcript_excerpt`,
  `diagnostic_metadata`;
- `AuthorizationScopeKind`: `machine`, `workspace`, `task`, `request`. Project membership is a
  grouping and coordination boundary; it does not add an egress scope kind;
- `RepositoryPrivacyAuthority.grant_state`: `granted`, `missing`;
- `RepositoryPrivacyAuthority.migration_state`: `not_applicable`, `legacy_route_available`,
  `first_repository_available`, `consumed`;
- `ConsentSource`: `none`, `baseline_policy`, `scoped_local_human`,
  `per_request_local_human`;
- `PrivacyOutcome`: `blocked_by_policy`, `blocked_forbidden_data`,
  `classification_uncertain`, `human_denied`, `approval_expired`, `channel_unavailable`,
  `provider_refused`, `timeout`, `invalid_response`, `transport_failed`, `late`, `stale`,
  `audit_failed`, `completed`;
- `PrivacyReason`: `policy_denied`, `never_send_detected`, `classification_uncertain`,
  `scope_mismatch`, `purpose_not_allowed`, `destination_not_allowed`, `category_not_allowed`,
  `channel_unavailable`,
  `human_denied`, `authorization_expired`, `authorization_stale`, `authorization_reused`,
  `insufficient_approved_context`, `provider_unavailable`, `provider_refused`,
  `provider_timeout`, `provider_invalid_response`, `transport_failed`, `audit_failed`,
  `deadline_expired`, `late`, `stale`, `outcome_unknown`;
- `ForbiddenDataKind`: `encryption_key`, `recovery_or_unlock_secret`, `password`,
  `api_credential`, `authentication_token`, `cookie`, `private_certificate`, `keyring_content`,
  `unrelated_environment`, `credential_file`, `hidden_auth_configuration`, `raw_database`,
  `unrestricted_log`, `raw_stderr`, `complete_transcript`, `out_of_scope_file`.

`DisclosureProvenance` is the closed authorship fact the `agent_context` ceiling is conditioned on:
`self_authored`, `other_writer`, `imported`, or `engine_derived_from_self_authored`. It is computed
server-side from the ledger, never asserted by a caller. An item is `self_authored` only when every
contributing accepted event was written by the requesting `writer_id` in this session at or before
the frozen frontier. Kernel prose derived solely from such events — a local finding's
`summary`/`detail` whose `subject_refs` are all `self_authored` — is
`engine_derived_from_self_authored`. AI-powered findings are never either value: reviewer prose is
provider-derived and stays under the ordinary ceiling. Import-derived material is always
`imported`, even when the importing writer matches, because the agent did not author what the
importer observed.

The `agent_context` ceiling is therefore provenance-conditional rather than a flat category set.
Items whose provenance is `self_authored` or `engine_derived_from_self_authored` project to the
requesting writer at the ceiling's data classes without needing a category grant: returning an agent
the prose it just published, or a local finding computed only from it, discloses nothing that host
does not already hold. Everything else — `other_writer`, `imported`, and all AI-powered findings —
requires the explicit `agent_context_categories` grant. `sensitive_confidential` and every
`ForbiddenDataKind` remain absolute regardless of provenance; self-authorship never unlocks a class,
only a category the host demonstrably already has. Provenance is recomputed at projection time
against the frozen frontier and is never cached across frontiers, and each projection still reserves
and completes its `AgentProjectionAuditSubject` receipt.

Undeclared-reference names (tb4n5, ADR-009 and ADR-035 amendments) use the same rule on exact
leaves. Status reads, at a head read, the accepted unredacted `action_recorded` `attempted_items`
and `obligation_published` `requested_items` values (excluding every event a `redaction_recorded`
targets by event ID or payload object ID, `events.redaction_targets`) that spell each
`/closure_readiness/undeclared_references/<n>/paths/<m>` path (whole, or as the tail of an absolute
spelling) and attaches that event's `SourceAuthorship` to the leaf, preferring the requesting
writer's own (`StatusInternalResult.leaf_authorship`, never in `as_json`). The service passes it as
`ProjectionProvenanceContext.leaf_authorship`, which admits only that leaf pattern; the resolver
matches a `repository_excerpt` item at exactly that pointer and applies `authorship_provenance`. So
a name returns only to the writer that published that exact text in this session through a
cooperative channel. The owner's allowance to show the agent names of files it itself created
(2026-10-13) is not implemented beyond this: the check-time change cannot tell a file the agent
created from one staged before the task, an ignored file force-added later, or one another process
wrote, and observation records no path for a shell-written file. A withheld name keeps the category
ceiling, and the Stop gate names the obligation item, the count and the omission, says FinishUP
returns only a name the agent published itself, and tells the agent to list its created files with
its own shell. Receipts, the MCP text summary, hook diagnostics and the review packet are unchanged
by it: only `full_local` receipts name the files, and the packet's history row of a check carries
their count, never their names, nor the digest of a payload that held them.

Production composes `LocalPrivacyEnforcer` with the ledger-authorship `TrustedProvenanceResolver`
(`build_local_privacy_enforcer`). Its only input is `ProjectionProvenanceContext.item_authorship`:
per projected row, the `SourceAuthorship` (writer, session, ingestion sequence, ledger-recorded
publication channel, observation-coordinator stamp) of each contributing accepted event, read by the
ledger at the page's frozen frontier and carried inside the service, never on the wire. Status
evidence rows are attributed; every other leaf resolves as ambiguous and keeps the category ceiling.
Self-authorship additionally requires a cooperative channel (`cooperative_mcp` or `local_cli`)
without the observation stamp, so hook-observed rows — written by the observation coordinator's own
writer — stay `other_writer` even when session and host match. Attach opens a new session with a
new writer, so rows published before it are not `self_authored` for the attached session. A row
whose source event a later `redaction_recorded` targets is withdrawn from attribution even on a
pinned read (`at_frontier` or an older cursor), so self-authorship never re-discloses redacted
prose; a later redaction of the source event's payload object counts the same as an event target.
A local-disclosure receipt lists an included self-authored category under its approved
categories without stating why; the `self_authored` provenance is recorded only in the internal
`AgentProjectionAuditSubject`, and surfacing it in `privacy receipts get` needs an egress-receipt
schema change that is a design-gated follow-up.

`PrivacyPolicyStorePort` alone loads/intersects and mutates the machine ceiling plus
repository/task/request overlays. Its `repository_authority(scope) -> RepositoryPrivacyAuthority`
read returns the bound scope, composed `EffectivePrivacyPolicy`, repository commitment,
`grant_state`, `migration_state`, `authority_digest`, ordered `PrivacyAuthorityAncestor` values,
and optional grant generation/digest as one snapshot. Standing external LLM admission requires
`grant_state == "granted"`; no machine row alone can satisfy it. Its
`seed_if_absent(policy) -> PrivacyPolicy` transition is the
only bootstrap write: it atomically commits the exact generation-1 denied machine policy when no
row exists, returns an existing row only when it is byte/identity-equivalent, and otherwise fails
with a bounded conflict without overwrite. First-child creation and a machine-ceiling plus
repository-row proposal are exact replay-safe atomic transitions CAS-bound to the authority digest.
The same transaction may consume one bounded pre-upgrade route or first-repository migration
entitlement. Stale ancestor movement, expiry, denial, or injected crash rolls back every member.
Legacy automatic carry-forward clones accepted bytes beneath the unchanged machine row and is
therefore classified as narrowing rather than a new approval. `PrivacyAuditPort` durably reserves
the closed
`PrivacyAuditSubject = PreDispatchAuditDecision | AgentProjectionAuditSubject |
DisclosureProposal` union, records exact
human decisions, mints one-use `EgressAuthorization`, exposes atomic consumption only to the
gateway, completes structural decision receipts for pre-dispatch terminal outcomes, and completes
one terminal structural attempt receipt per physical attempt, including taskless channels, and
atomically consumes/completes receipt-bound local disclosures. Agent projection subjects contain
only installation-keyed result/projection commitments and field decisions, never copied plaintext.
Internal `PrivacyAuditPort.load_disclosure_attempt(request_id, case_digest)` resolves one physical
disclosure attempt to its real audit state and HMAC subject identity. It authenticates the
structural sidecar, rejects conflicting/ambiguous request bindings, and distinguishes exact
absence from unavailable or corrupt storage. Admitted recovery preserves the proposal/request
identity; consumed or completed admission cannot authorize another dispatch. This lookup is not
an MCP or control-wire method.
Both audit adapters require an exact string request ID in the `req_` UUID-v4 vocabulary and a
lowercase `sha256:` digest. Wrong Python types raise `TypeError`; malformed strings raise
`ValueError`, both with `privacy_disclosure_attempt_lookup_invalid`. The authenticated catalog
sidecar must contain a valid `prepared_case_digest`: missing or malformed values are
`privacy_audit_attempt_corrupt`, while a valid different digest is
`privacy_audit_attempt_case_mismatch`. Only exact absence returns `None`; storage errors propagate
and never authorize a fresh attempt (issue #626).
Internal `PrivacyAuditPort.get_receipt`/`list_receipts` queries project bounded structural views
only through the ordinary CLI/UI control methods `privacy_receipts_get` and
`privacy_receipts_list`; the port names are not wire aliases and MCP has no access. Both methods
are bound by `build_privacy_support_handlers` whenever the privacy application is composed, so a
ready service answers them rather than `method_forbidden` (issue #730). Their bodies carry
`schema_version` `1.0.0`: `get` takes `receipt_id` and answers `outcome` `found` with one
`receipt` wrapper or `outcome` `not_found`; `list` takes `filters`, `page_size` (1–100) and an
optional `cursor` and answers `snapshot_generation`, `receipts`, and `next_cursor` only when
another page exists. Each wrapper names its `kind` (`local_disclosure` or `network_egress`) and
carries the receipt in the `privacy/egress-receipt-1.0.0` vocabulary: every counter and version
is a decimal string, optional fields are absent rather than null. `counts.final_bytes` is bounded by
that vocabulary's 262,144 in the domain too (`MAX_RECEIPT_FINAL_BYTES`), not by the 512 KiB
outbound-document bound, so the store can no longer hold a receipt the wire refuses. Unknown or
malformed keys, filters, page sizes, cursors, and receipt IDs are `invalid_request`; a cursor minted
for a different query is the same non-retryable rejection, and `invalid_request` is reserved for
those caller mistakes (issue #921). Stored rows are read one at a time: a row that cannot be read
back -- it does not decode, its receipt fails the domain bounds (for example a `final_bytes` above
262,144 written by an older build), or its own bytes disagree with the indexed
`receipt_id`/`receipt_finished_at` the page is ordered by -- is skipped, never allowed to fail the
page. The skip is counted and named: the 2.9 result carries `undecodable_count` (decimal, 1-100) and
`undecodable_receipt_ids` (the structural ids of the skipped rows whose id is intact) together and
only on a partial page, so a complete page keeps its exact bytes; the first five skipped rows of a
page also each leave an owner-only `privacy_receipts_list_row_skipped` diagnostic whose reason names
the destination kind and whose `request_id` is the row's own, so a heavily corrupt audit listed
repeatedly cannot evict unrelated records from the bounded diagnostics ring. The cursor carries the
last listed row's `receipt_finished_at` and `receipt_id` text as stored and compares it as text, as
the ordering does, so it advances past skipped rows and a corrupt row can end one page without
stranding the pages behind it; paging neither repeats nor loses a row. A row whose stored finish
time is not a canonical timestamp is kept in the listing and skipped as unreadable rather than
falling outside the snapshot bound. A failure of the store itself -- an unreadable row fetched by
`get`, an ordering or uniqueness violation among rows that did decode, an unavailable snapshot
generation, a malformed cursor whose MAC and query digest verified (only this store could mint it)
-- is the closed, non-retryable control reason `privacy_audit_unreadable` (public code
`STORAGE_CORRUPT`, exit 40, continuation `privacy_audit_review`) with a correlation id the
diagnostic sink resolves; the client reports a frame it validated but cannot decode into receipts
the same way. The CLI prints a partial page in full and exits 40 with the count and ids on stderr.
Both audit adapters project stored network
egress receipts as well as local disclosure receipts, so a completed subscription review is
retrievable by its recorded receipt ID and listable by `channel`, `provider_id`, or
`endpoint_profile_id`. A network receipt may also name its closed `origin_operation`
(`semantic_check`, `observation_advice` or `credential_probe`; egress-receipt 1.1.0, ADR-009
tb4n2 amendment), derived from its purpose and reserved structural item ids and omitted when not
recognized, so a recurring blocked receipt can be traced to the operation that asked for it.

A receipt's `purpose` has two owners, and they are deliberately not the same grammar. Anything
crossing the privacy-policy boundary — every network egress receipt, every
`ChannelPolicy.allowed_purposes` entry, the `privacy/egress-receipt-1.0.0` and
`privacy/privacy-policy-1.0.0` schemas — uses the external vocabulary
`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$` (hyphenated, no underscores): `semantic-review`,
`credential-probe`, `package-update-check`. Local disclosure receipts additionally carry the
product's own sink-local purposes, which never reach a provider, are never policy-admitted, and
whose canonical owner is `finishup.domain.privacy`'s wider `^[a-z][a-z0-9_-]{0,127}$`. The
agent-projection purpose `client_result_projection` is one of these: it is fixed by the
`agent_projection` CHECK in `migrations/catalog/0001.sql` and is part of every stored receipt's
canonical bytes and digest, so it cannot be renamed. Control result `2.6.1` (the 0.2.3 repair)
and every later result envelope, including the 0.3 line's `2.7.0`, `2.8.0` and `2.9.0`, therefore
validate `local_disclosure_receipt.purpose` against their own `local_disclosure_purpose` definition,
mirroring that domain grammar, while network egress keeps the stricter external reference. Before
`2.6.1` the local branch reused the external grammar, so every ordinary local receipt failed the
result envelope and `privacy receipts list`/`get` answered `read_projection_failed` (issue #732);
the frozen `2.6.0` and earlier envelopes keep their released bytes. Hello envelopes stayed `2.6.0`
on the 0.2 line; the 0.3 line's `2.7.0`, `2.8.0` and `2.9.0` request and result envelopes derive
from `2.6.1` and add no second grammar. CLI JSON, terminal output and the prompt-loop menu render
decoded UTC receipt timestamps in canonical millisecond RFC3339 form (issues #731 and #732). The
0.2.3 schema inventory is reported by version-manifest `2.2.1`, the 0.2.4 inventory by `2.2.2`,
and the 0.2 line's setup-readiness and setup-status additions by `2.2.3` and `2.2.4`; the 0.3
line reports its inventory, including both setup contracts and `isolation-report` `1.0.0`
(issue #567), through `2.3.0`. Manifests carried from the 0.2 line retain their bytes.

`PrivacyAuditPort.list_pending_disclosures(audience) -> PendingDisclosurePage` projects only
`PendingDisclosureEntry(pending_id, task_id, expires_at)` for proposals in `awaiting_human` or
`reserved` whose `expires_at` has not passed, over the ordinary CLI/UI control method
`privacy_pending_list` (schema token `yoetz.privacy-pending-page/1`). It names which decisions a
local human can still make and never the destination, categories, digests, or prepared bytes of
any of them: that content belongs to the confidential decision preview, which is bound to the
exact prepared case. MCP has no access. Initial
reservation failure is the sole no-receipt exception and occurs before prompt/authorization/
dispatch; `awaiting_human`, `approved`, and `receipt_pending` are nonterminal
`PrivacyAuditState.status` values rather than receipt outcomes.
`PrivacyAuditPort.live_object_roots(task_id, route_identity_digest) -> PrivacyAuditObjectRoots`
returns the monotonic catalog generation, sorted task-bundle `privacy_audit` ObjectRefs, and canonical
root digest used by GC/backup/restore/recovery. These are live without task-ledger inventory.
`PrivacyClassifierPort` classifies locally and performs deterministic minimization/redaction and
secret scanning. `HumanPrivacyControlPort` exists only in trusted local-human composition and
cannot be implemented by MCP, an agent, an LLM, a plugin, or ordinary noninteractive workflow
input. `OutboundGatewayPort` is the only network-capable application effect, accepts only an exact
`ApprovedOutboundCase` plus a still-valid unconsumed authorization, and atomically consumes that
authorization through `PrivacyAuditPort` immediately before adapter I/O. Policy tightening and
external/local consume share one generation CAS: tightening-first means no I/O; consume-first means
one admitted attempt may send, is best-effort closed/nonselectable, and receives its actual receipt.
`OutboundGatewayPort.reconcile_policy(policy, human_authority: HumanAuthorityCapability)` remains
the port's compatibility entry point and cannot invent repository authority. Repository-aware
composition calls the concrete gateway's
`reconcile_repository_policy(policy, human_authority, *, repository_privacy_commitment,
authority_digest)`, which binds the machine/repository/task/request composition, exact repository
commitment, authority snapshot, and human-authority generations. Unavailable authority or a
missing or mismatched exact repository grant yields an empty external registry before credential
minting.
`PolicyEnforcingOutboundGateway.has_connected_provider_binding(binding)` is the composition-only
exact-binding liveness query over that registry; it never probes or mints a credential.
`OutboundGatewayPort.close()` is an idempotent terminal operation: it installs a deny fence before
awaiting transport closure, after which reconciliation/dispatch/revocation admit no new work, mint
no credential, render no content-bearing request, and perform no new adapter I/O. Unconsumed work is
fenced before I/O; a consumed attempt is only best-effort closed/nonselectable and still receives
its actual or `outcome_unknown` durable receipt.
A consumed authorization ends in exactly one terminal receipt, cancellation included. The gateway
owns that receipt because only it holds the exact final request body, its keyed
`request_commitment`, and the authorization/registry binding a dispatch receipt must carry.
Immediately after the consume CAS it builds the `transport_failed/outcome_unknown` receipt the
attempt would owe and parks it through
`PrivacyAuditPort.park_attempt_reconciliation(dispatch_id, receipt)`; parking asserts no outcome and
leaves the row `receipt_pending`. `asyncio.CancelledError` inside that admitted window (a foreground
runtime rebind yielding an advisory attempt) records the parked receipt through a shielded
`complete_egress` and then re-raises, so cancellation still propagates promptly and no provider is
re-entered. `PrivacyAuditPort.reconcile_started_attempts(consumed_before, limit) -> int` is the
bounded, idempotent startup sweep for rows whose dispatcher died before that write: it runs once
before any supervisor may admit a new physical attempt and considers only attempts consumed
strictly before the current service start, so a live dispatch is never closed. Local-sink
`local_disclosure_pending` cancellation is outside this contract. `PrivacyCoordinator.close()` installs its own
terminal admission fence first and closes the gateway exactly once; it neither returns credential or
content nor erases durable policy/audit state, so pending durable work may resume only in a fresh
ready coordinator.

For a physical attempt, the deterministic adapter first renders the exact final provider/application
request body, performs the final exact-body scan, and computes
`privacy_request_commitment(final_request_body, audit_mac)` once using only a
`MacKeyHandle(purpose=privacy_audit)` and commits to those body bytes after all approved transforms
before credential binding and the consume CAS. Consumption is the later last authority transition;
the custom transport equality-checks the unchanged bytes/commitment before header injection/I/O
without recomputing the MAC. HTTP/TLS framing, transport-generated fields, and
credential-bearing authentication metadata are excluded; no claim equates the commitment with all
wire bytes. The receipt uses `audit_store_version=1` and closed
`request_commitment={algorithm:"hmac-sha256/yoetz-privacy-egress-request-v1", commitment:
"hmac-sha256:<64 lowercase hex>"}` with no `key_slot_ref`; `dispatch_id` requires exact
`counts.request_body_bytes`. A separately bound `ProviderCredentialHandle` injects authentication only at the
transport boundary and cannot change or add user-content body fields.

Receipt domain values are schema-shaped: `EgressReceipt` and `LocalDisclosureReceipt` require
`schema_version="1.0.0"`, their complete structural identities, `ReceiptPolicyBinding` including
authorization-scope digest, `ReceiptCounts`, `ReceiptTransformations`, and `ReceiptSecretScan`.
Network egress additionally requires the exact channel-compatible `ProviderBinding |
NonLlmDestination`; local disclosure names its sink and forbids attempt-only request-body counts.
Required schema data is never modeled as an optional compatibility default.

Predispatch `EgressReceipt.blocked_categories` contains only actual classifier/category-policy
denials (#1019). Request-level scope/destination/channel refusal and failure to assemble approved
context do not by themselves deny any category. `approved_categories` and `counts.approved_items`
record classification approval, never provider delivery; before classification neither approval
nor denial is asserted. `safe_failure_reason` independently names the actual failure. Stored older
receipts preserve their original category accounting. Because the released receipt shape is
closed, the human rendering of `finishup privacy receipts get|list` (not `--json`) adds one stderr
line per network receipt with no `dispatch_id` that still carries approvals: `not sent: privacy
receipt <receipt_id> (<outcome>) never reached a provider; ...` (#1019 r2).

`EgressReceipt` and `LocalDisclosureReceipt` share one closed outcome/reason compatibility matrix:
`completed` forbids `safe_failure_reason`; every other outcome requires exactly one reason permitted
for that outcome. `blocked_by_policy` admits the direct policy/scope/category/purpose/destination
reasons plus `insufficient_approved_context`; `approval_expired` admits
`authorization_expired|authorization_stale|authorization_reused`; all other pairings are exactly
the table in the privacy protocol/receipt schema. Cross-pairs and missing failure reasons are invalid.
At the final approved-dispatch guard, an expired disclosure proposal remains
`approval_expired/authorization_expired`, while an exhausted in-process `Deadline` is
`timeout/deadline_expired`. Both block provider dispatch; the distinction identifies whether human
approval or the execution budget expired.

Shared privacy values are `ProviderBinding`, `AuthorizationScope`, `ChannelPolicy`,
`PrivacyPolicy`, `PolicyOverlay`, `CandidateContext`, `ClassifiedContext`, `PrivacyDecision`,
`PreDispatchAuditDecision`, `DisclosureProposal`, `PrivacyAuditSubject`, `HumanPrivacyDecision`,
`PrivacyAuditReservation`, `PrivacyAuditState`,
`PendingHumanDecision`, `PreparedOutboundCase`, `EgressAuthorization`, `ConsumedAuthorization`,
`PrivacyAuditObjectRoots`,
`ApprovedOutboundCase`, `ApprovedLocalDisclosureCase`, `ApprovedProviderCase`, `EgressReceipt`,
`LocalDisclosureReceipt`, `EffectivePrivacyPolicy`, `PolicyTransitionProposal`,
`PreparedPolicyTransition`, `HumanPolicyDecision`, `HumanAuthorityCapability`, and
`ProviderReconciliation`. Provider adapter interfaces never accept a
`CandidateContext`, and closed composition supplies reviewed bundled adapters no repository,
bundle, transcript, environment, log, database, or keyring handle. Third-party/dynamic adapters are
absent; this is not an OS sandbox against malicious code already inside the trusted service. Policy
widening requires a reauthenticated decision by the user: either the trusted local ceremony, bound
to the exact diff/digest and shown the complete `before → after` change set that produced the
widening classification, or the user's explicit current-chat instruction for one exact prepared,
previewed, expiring consent target relayed by a capable agent through the consent lane (ADR-009
"Human required?" table; ADR-016 decision 5), which is an agent attestation FinishUP cannot
independently authenticate; tightening is immediate after an ordinary explicit confirmation and
revokes affected authorizations/transports. The never-send set is non-overridable under either
path.

The scanner keeps concrete credential findings separate from low-confidence assignment heuristics.
When the sink policy permits it, an item with only a heuristic match carries its surrounding bytes
with the matched span replaced by `[REDACTED]`; its original digest, transformed digest, scanner
profile, and bounded redaction count remain distinct. Structured JSON/history content keeps its
syntax while the value span is replaced. Provider-bound content rows mark that transform with the
existing `redacted`/`sensitive_redacted` transformation vocabulary so recovery can validate the
exact transformed manifest even when the item was not a targeted excerpt. An ambiguous or
untransformable heuristic remains
withheld, and a safe review of clean siblings may continue with an explicit coverage class. A
concrete credential, mixed finding, scanner saturation or failure, stale policy/scanner manifest,
and any final rendered body match remain whole-case no-dispatch refusals. The final-body backstop
scans heuristics too, so a transformation failure cannot turn into disclosure. Recovery persists
the transformation/withholding identity with the exact proposal; a corrected check supplies a new
prepared case. No matched bytes, caller prose, raw exception, or detector output enters a
structural notice or receipt.
The check result and CLI/TUI rendering expose bounded transformation or withholding facts; MCP,
hook-relayed, and receipt projections use the same fields. Privacy receipts mark the secret-scan
stage as `candidate`, `prepared_case`, or `rendered_body` when that scan actually ran. `not_run` is
explicit and carries its closed reason; a clean `passed` value is never used as a placeholder for a
scan that did not execute.
Only unquoted parser/member/call/enum expressions with source syntax evidence are excluded: a
`const`/`let`/`var` declaration for a token call or member call, an explicit member assignment
such as `parser.token = Token.EOF`, a lower-case object property such as `token:
Token.ConstKeyword`, or a lower-case Python `token = node.token` assignment inside a valid
function. Bare dotted assignments such as `TOKEN=opaque.value` or `token=opaque.value`,
call-shaped values such as `password=functionName()`, quoted lookalikes, mixed-language text, and
malformed source remain withheld. This precision rule does not add an opt-out.
Since issue #982 the assignment heuristics also skip values that cannot be credential material:
comparisons and walrus operators (`token == x`, `token := x`); an unquoted next key after a line
break (an empty `KEY=` followed by `NEXT=`); unquoted language literals and type names (`None`,
`True`, `str`, `Optional`); unquoted `self.`/`this.`/`cls.` attribute values; for password,
secret and API-key names, an unquoted call or subscript on a name (`get_secret(`, `secrets[i]`),
`|>`, or a digit-free documentation placeholder (`<your-api-key>`, `${MY_PASSWORD}`, `gw_...`);
and, for `*token` names only, unquoted values containing `()[]<>|` or a backtick, unquoted
numbers, documentation placeholders (`<...>`, `${...}`, `{{...}}`, a trailing `...`), values
shorter than eight bytes, digit-free snake/constant identifiers, and values with characters
outside opaque token material (whitespace, brackets, braces, parentheses, pipes, quotes).
Password, secret and API-key values keep every other shape, including punctuation-heavy values
such as `p<ss>w0rd|x` or `Summer2024...`. A marker followed by more bytes
(`TOKEN=[withheld-by-yoetz:possible-credential]rest`) still matches. Typed declarations
(`password: str = "..."`, value span only) and JSON-escaped keys (`\"password\": \"...\"`) match.
Capture-time redaction covers only high-confidence findings; heuristic-only matches are redacted
at egress.

`PreDispatchAuditDecision` is structural-only and terminal; it permits no prepared bytes,
authorization, or dispatch. A v0.1 content-bearing `DisclosureProposal` has one owning `task_id` and
is encrypted as `ObjectKind.privacy_audit` in that task bundle; the privacy catalog stores its
`ObjectRef`. Taskless v0.1 decisions and policy diffs contain only closed nonsecret structural
fields. No taskless content-bearing channel can activate until an installation-scoped encrypted
audit-object owner/key/storage/retention contract is added.
Catalog privacy content refs remain roots for the supported installation-data lifetime in v0.1;
ordinary ledger redaction cannot target/clear them, and no individual privacy-audit deletion use
case exists yet. A missing/tampered root quarantines the audit row and fences content disclosure
without inventing a ledger row or clearing evidence.

`ConsentSource.per_request_local_human` under `confirm_every_request` authorizes exactly one
physical dispatch. Resume before authorization consumption continues that same dispatch. Every
physical retry after consumption requires a fresh proposal, exact foreground preview/decision,
authorization, dispatch ID, credential handle, and receipt even when body bytes are identical.
Automatic profiles may mint retry attempts from baseline policy only within the one total
retry/deadline budget; no branch reuses consumed authority.

`PrivacyPolicy` contains the explicit `review_context_profile`, its compiled
`ReviewSelectionPolicy`, editable `require_current_provider_data_use_evidence` boolean,
`network_egress_permitted` global ceiling, plus all five exact `ChannelPolicy` rows. A false ceiling
requires every row disabled; a true ceiling grants nothing. The `llm_inference` row may carry
`fallback_provider_binding` (issue #582): a second exact external `ProviderBinding` that must
differ from `provider_binding` and is valid only behind an external primary;
`ChannelPolicy.authorized_provider_bindings` is the closed tuple, primary first, at most two.
Egress admits a candidate only when its binding is exactly a member of that tuple; the registry
admits each member on its own. The policy diff vocabulary gains
`("channel", "fallback_provider")`, rendered "Fallback provider and model" and ordered right
after the primary in the Destination group; adding or changing the fallback is a widening,
removing it a tightening. Intersection keeps a fallback only when both scopes name the
identical one. The field is introduced in `privacy-policy-1.1.0` as optional and emitted only when
present, so single-endpoint policy digests are unchanged. `credential_heuristic` (issue #982,
owner opt-out) is `enforced` (default; absent means enforced) or `disabled`. `disabled` reaches only
external AI-reviewer egress (an LLM-inference candidate with an external provider binding and no
local sink; `external_review_credential_heuristic`): its classification, minimization and
prepared, rendered-body and resume scans ignore low-confidence assignment matches. Every local
output (agent context, local model, local and trusted human views) keeps the heuristic. High-
confidence findings (known credential shapes, private-key markers, URI passwords, canaries,
scanner saturation) always block or redact. The applied value travels on `ClassifiedContext` and
`ApprovedOutboundCase` (`PrivacyClassifierPort.scan_exact_bytes(..., credential_heuristic=...)`),
and every external receipt prepared under it records `secret_scan.credential_heuristic:
"disabled"` (egress-receipt 1.1.0; absent when enforced). The policy diff vocabulary gains
`("global", "credential_heuristic")`, a flag rendered "Possible-credential filter" in the
Information disclosed group, ordered right after `provider_data_use_evidence`; turning it off is a
widening, back on a tightening. The setting belongs to the repository grant: composing the
installation row with a repository row takes the repository row's value, the installation value
is only the default a new grant is drafted from (a repository-bound proposal never moves it), and
any narrower composition keeps `enforced` unless both sides are `disabled`. Status-result 1.4.0
carries the optional `credential_heuristic` object (`repository`, `machine_default`, each
`enforced`/`disabled`/`unknown`), composed by the service on every status from the repository
setup read, which carries the same pair (control-result 2.9.0 `privacy_get_setup_body`, optional;
`credential_heuristic_state` over `RepositoryPrivacyAuthority.machine_policy` and
`migration_frontiers`). A repository without a grant reads `enforced`, except under a pending
migration (`legacy_route_available`, `first_repository_available`), where it reports the meet of
the frontier and the installation row the first check will create, or `unknown` when frontiers
disagree. The field is written only when `disabled`
(privacy-policy wire 1.2.0 minimum; 1.0.0/1.1.0 documents naming it are rejected), so every
existing policy, meet and receipt digest is unchanged. `PrivacyProfile` governs the
`llm_inference` row/content rules only; `ReviewContextProfile` can only narrow which case items are
considered and never grants a category, class, destination, scope, or byte. `local_only` disables
external LLM construction and external task/user-content disclosure but is not a bundled decision
for the four non-LLM rows. `ReviewSelectionPolicy` is the closed sections/excerpt-kinds/relevance/
finding-prose/exact-command/caps value owned by `domain/privacy.md`; overlays meet by set
intersection, stricter relevance, logical AND for both booleans, and minimum caps. Selector growth
or disabling the current-data-use guard is a policy loosening. Among those four rows, v0.1 owns a
production transport only for `update_checks`: a bounded structural PyPI transport behind a real
setup yes/no (product default on). Setup renders the remaining three rows `unsupported`; enabling
them returns
`channel_unavailable` without persistence or I/O, and forced enabled state for those rows yields a
pre-dispatch `channel_unavailable/channel_unavailable` decision receipt with no
authorization/dispatch/commitment/attempt-body fields. A later exact capability for those rows
requires a fresh local-human policy transition and cannot activate dormant v0.1 intent.

### Package update advisory

Interactive-only structural DTO (`finishup.application.package_update.PackageUpdateAdvisory`):
`outcome` (`newer_available|up_to_date|skipped_policy|skipped_unavailable|skipped_unknown_version`),
`installed_version`, `latest_version` (nullable), `is_newer`, `upgrade_command`
(`finishup upgrade`), `source` (`network|cache|none`). Setup reports may include a
`package_update` object with the same field names. Work receipts and ledger documents never carry
these fields.

`ProviderBinding` is exactly the five nonsecret fields `provider_id`, `model_id`,
`endpoint_profile_id`, `endpoint_profile_version`, and `transport` (`external|local_af_unix`); it
has no URL, socket path, credential, header, or open options map. `AuthorizationScope` is one closed
ancestor-preserving union: every kind carries `kind` plus `installation_id`; workspace/task/request
add `workspace_ref_commitment`; task/request add `task_id`; and request adds `request_id`. Fields
from a deeper kind are forbidden at shallower scope, and a generic `scope_ref` is never valid. For
privacy authority, `workspace_ref_commitment` is populated from the trusted
`repository_privacy_commitment`, not from `StartIdentityInput.workspace_ref`; the shared wire field
name does not make those two commitment domains substitutable.

Every installed external endpoint profile also carries a nonsecret, versioned
`ProviderDataUseProfile`: `data_use_profile_id`, `data_use_profile_version`,
`customer_content_training` (`prohibited|permitted|unknown`), `retention`
(`none|bounded|unbounded|unknown`) with an exact ceiling only when bounded,
`provider_human_access` (`prohibited|restricted|permitted|unknown`), `reviewed_at`, `expires_at`,
and an artifact-bound evidence
digest. It is recommendation metadata, not policy authority or proof of provider behavior. Upstream
`assisted` recommendation eligibility requires `reviewed_at <= now < expires_at`, training
`prohibited`, retention `none|bounded`, and any bounded ceiling no greater than 30 days. Provider
human access and documented legal, safety, support, and abuse-monitoring exceptions remain review
facts. The recommended policy's explicit guard turns currency into a runtime precondition; a custom
policy may turn it off through a trusted loosening transition and then carries no upstream
no-training claim.

### AI-powered evaluation

External AI-powered review provider profiles declare one credential authority.
`finishup_vault_api_credential` means the ready service mints an attempt-bound vault handle for an
exact HTTP provider profile. `external_runtime_oauth` means an exact vendor runtime owns login,
refresh, storage, and upstream authentication; the gateway supplies only
`ExternalRuntimeAuthority(dispatch_id, request_body_digest, request_commitment, service_generation,
monotonic_deadline)`. The two authorities are bound alone or paired as one primary plus exactly one
fallback (issue #582); nothing else pairs.

**Fallback endpoint pairing (issue #582).** `[semantic_fallback]` is a nonsecret config table
(`SemanticFallbackConfig`; `yoetz-config-1.2.0`, with `1.1.0` frozen) with the single field
`primary = "api_provider" | "codex_subscription"`. `api_provider` is `[provider]`
(`finishup_vault_api_credential`); `codex_subscription` is `[external_runtime]`
(`external_runtime_oauth`); the other bound table is the fallback. Both tables must be bound
(`semantic_fallback_endpoint_missing`), `[local_model]` stays forbidden
(`external_runtime_forbids_local_model`), and `profile` must name the primary — `local-openai`
for `api_provider`, `codex-subscription` for `codex_subscription`
(`semantic_fallback_profile_mismatch`). `primary_external_endpoint(config)` and
`fallback_external_endpoint(config)` are the only readers of the roles; without a pairing the
first returns the single bound table and the second `None`. CLI: `finishup provider endpoint ...
--as-fallback` binds an API provider as the fallback behind an already-bound subscription (then
`finishup provider credential set` as usual); `finishup provider codex-subscription setup ...
--as-fallback` binds the subscription as the fallback behind an already-bound API provider; both
report `endpoint_role`. `finishup provider fallback remove` drops the fallback and its selector,
restoring the exact single-endpoint shape; `finishup provider fallback primary
<api_provider|codex_subscription>` swaps roles with both bindings kept; both refuse without a
pairing (`semantic_fallback_endpoint_missing`, exit 2). `finishup provider codex-subscription
disconnect` inside a pairing leaves the API provider as the sole endpoint. Rebinding one slot
inside a pairing without `--as-fallback` keeps the selector and replaces only that slot. The
service advertises a `fallback_provider` capability when the fallback's credential is
structurally present; it is never an input to `semantic_ready`.

Dispatch (`application/semantic_attempts.py`, `service/ready_composition.py`): the primary is
given up for the fallback only for the closed fallback-licensing set —
`timeout/provider_timeout`, `unavailable/transport_unavailable`,
`unavailable/provider_rate_limited`, `unavailable/provider_quota_exhausted` — after
`FALLBACK_PRIMARY_FAILURE_LIMIT = 2` such failures, one quota exhaustion, or the primary's
exhausted retry budget; a primary unresolvable before dispatch (`credential_unavailable`) hands
every attempt to the fallback with zero primary attempts. Content-shaped outcomes
(`response_content_invalid` including the #348 repair retry, `response_schema_invalid`,
`refused`, `semantic_judgment_rejected`), policy/human outcomes, and `outcome_unknown` never
engage it, and an engaged job never returns to the primary. Each endpoint keeps its own ADR-006
retry budget (at most two retries) and its own configured timeout; the operation deadline is
the primary timeout plus the fallback timeout. Primary dispatch uses its own frozen cutoff;
fallback dispatch uses the first fallback attempt's durable `started_at` plus its frozen timeout,
capped by the overall cutoff. Neither retries nor replay reset these clocks. Time exhaustion alone
does not bypass the closed engagement rule. The encrypted `yoetz.semantic-case/2` object freezes
endpoint bindings, initial readiness, retry budgets, and cutoffs. `endpoint_role_for_ordinal` derives
the endpoint from this frozen plan and durable prior rows, so changed configuration cannot relabel
an attempt on replay. Legacy terminal cases recover their stored result; a legacy pending case
without frozen execution authority terminates without dispatch: `coordinator_failure` before
dispatch or during a disclosure wait. A task-local `awaiting` row can lag the independent privacy
audit and does not prove an expired started attempt was never admitted. Deadline recovery keeps
that attempt `outcome_unknown` without re-entering authorization, retry, or fallback; a new,
unattempted job still reports `provider_timeout` (issue #625). An uncertain started attempt retains `outcome_unknown`
in its durable row; without reconstructable provider provenance its public gap is
`receipt_persistence_unknown`. Each
fallback attempt is a fresh physical attempt with its own authorization, dispatch id, credential
handle or runtime authority, and privacy receipt; under `confirm_every_request` it needs its own
foreground decision. `SemanticAttemptAccounting.endpoint_attempts` carries one per-endpoint
slice (`role`, identity, `attempted_count`, `terminal_reason_counts`, `last_terminal_reason`,
`predispatch_reason`), empty for a single-endpoint job. Provenance carries `fallback_from`
(below) exactly when the fallback served.

`codex-chatgpt-subscription@1` is the only v1 external-runtime profile. Its configuration is the
closed `ExternalRuntimeProfileConfig`: exact absolute executable and dedicated-home paths;
executable, app-server-schema, capability-cell, and isolated-config SHA-256 digests;
runtime/source/capability identities; capability-evidence expiry; model; reasoning effort
(the final-profile effort); timeout; and retry cap. It also has the optional
`routine_reasoning_effort` (absent means routine checks keep `reasoning_effort`) and
`routine_output_limit`/`final_output_limit` (output tokens, 1–8192, defaults 4096/8192). The
writer emits these three keys only when they carry an explicit choice. It has no token, OAuth
endpoint, generic provider URL, headers, or open options map. Expired capability evidence fails before child launch. `account/read`, model
discovery, login, and logout are structural app-server operations and never a task-content probe.

`SemanticEvaluatorPort.evaluate(case: ApprovedProviderCase, deadline: Deadline) -> SemanticResult`
makes at most one physical provider request. `SemanticResult` is the closed union
`SemanticResultSuccess | SemanticResultRefused | SemanticResultTimeout | SemanticResultInvalid |
SemanticResultLate | SemanticResultUnavailable`; expected refusal, timeout, invalid, late, and
unavailable outcomes are values. `SemanticCase` remains an internal pre-egress candidate and is
never provider input. It contains a structured `ReviewPacket`: goal and obligations, claims and
decisions, a material ordered timeline, local findings plus `FindingBasis`, change observations,
coverage, targeted recorded excerpts, and an omission manifest. The owning `DeterministicCase`
freezes a canonical material-history tail before AI-powered review selection: at most 64 accepted
plan, obligation, decision, action, result, evidence, claim, finding, response, and check events, in
ingestion order, with at most 512 KiB of canonical payload. Payload retention is newest-first;
over-budget retained payload is `not_selected`, legacy history is `not_recorded`, source redaction
is `redacted_never_send`, and an exact omitted-before count represents older events. `structural`
emits only event identity/order/digest/visibility as `bounded_structural_metadata`. Goal-aware
detail is emitted as separate `task_description`, `obligation_text`, `claim_text`,
`decision_excerpt`, `command_metadata`, `evidence_excerpt`, or `finding_summary` items. Exact action
command text is removed unless `include_exact_command_text` is independently true. Every item
remains separately policy-selected, scanned, authorized, and receipted; the frozen slice grants no
egress authority. Its reference allowlist is the union of `frontier_refs` (IDs present at frozen
frontier F) and `local_check_refs` (new local finding IDs already pinned in this check's durable
local result); both sets and their union are case-digest inputs. The AI-powered review
`frontier_refs` set is the dependency closure of retained packet metadata, canonical payload items,
recorded findings, and their typed recorded dependencies/source-event identities. It may be smaller
than the local-check case's complete allowlist. `omitted_reference_count` counts the excluded
frontier IDs, is bound into the case digest, and travels as a canonical integer string in the
envelope and assembled packet. `semantic_reference_scope_reduced` marks the packet, check, status
and receipt coverage as partial; selection grants no additional content/disclosure authority.
Captured prose is not scanned to invent structural dependencies. The complete local-check case and
its integrity checks remain unchanged. The code is disclosure, not a proof limitation of the local
case (#904): it never blocks resolution of a local finding. For an AI-powered finding it joins the
capture baseline, so it blocks when it is new since the review that raised the finding. It also
blocks when the later check's `semantic_included_refs` (the references whose content the sent
packet carried) lack the finding's subjects, its response-linked repair material, or a change made
after it (see the #904 resolution paragraph below).

Recorded parent lineage enters the case as structural items only: identities, lifecycle, freshness,
coverage tokens, and finding identities. A document that fits in one 16 KiB item stays
`yoetz.lineage-semantic-input/1` with item id `lineage`. A larger legal fan-out is split into
complete `yoetz.lineage-semantic-input/2` parts (`lineage-00`, `lineage-01`, ...) that together
retain every child and gap plus the shared manifest digest. The review-text helper does not cut
these items at 4 KiB. A single fact that cannot fit, a partition that would exceed the timeline
item budget, or lineage plus retained parent content exceeding the 256 KiB complete-case budget
raises before dispatch. Composition maps that to `failed/case_capacity_exceeded`
with diagnostic operation `semantic_not_dispatched_lineage_capacity`: no job, no provider call,
and the local result unchanged.

If the retained required structure still exceeds 131,072 bytes, AI-powered review composition
returns `failed/case_capacity_exceeded` before creating an AI-powered review job or invoking a
provider. This additive reason belongs to the current 1.1 check/provenance schemas; released 1.0
schemas retain their original bytes. Local findings remain recorded; no provider attempt is consumed
and provenance stays null. The shared check/receipt gap is `semantic_case_capacity_exceeded`. A
narrower claim/obligation scope is a new check, not a replay of the terminal request. Changing a
text length or finding limit alone does not guarantee enough capacity.

`TargetedExcerptRef` identifies a bounded excerpt already captured or agent-published inside the
frozen case and links it mechanically to a claim, obligation, finding, action, result, or evidence
ref. It grants no live Git/filesystem access. When the source evidence carries a typed
`digest_binding`, the excerpt text prefers the bounded caller-authored `description` and the ref
carries the digest identity facts as an optional `ExcerptDigestProvenance`
(`evidence_kind`, `strength`, `content_digest`, `digest_subject`, `content_availability`,
`byte_count`, `provenance`, and the approved-check pair when present); a digest-bound record
without a description contributes its canonical provenance facts as the excerpt text, unchanged. `ChangeObservation` keeps `claimed_change`, existing
three-valued `subject_state_relation`, and `content_visibility`
(`available|not_recorded|not_selected|withheld_by_policy|redacted_never_send`) separate, so absent
code can never become “no code changed.”

`SemanticJudgment` contains only a closed conclusion plus zero to three bounded
`ReviewerChallenge` values; each accepted challenge is the sole candidate-producing shape, so no
parallel candidate/challenge pair can duplicate it. A challenge has case-bound `cited_refs`,
discrepancy, alternative interpretation, direct main-agent message,
`requested_next_step` (`act|provide_evidence|revise_claim|dispute_with_evidence|
state_unresolved_limitation|answer_question`), and uncertainty. `answer_question` (issue #976) asks
the agent a question it answers in the `respond` reason; `acknowledged` on any AI-powered finding
requires a non-empty reason. Post-validation resolves every cited action/result/
evidence/frontier-finding/local-check-finding ref to its canonical frozen event/obligation/claim
roots; only those roots become public `Finding.subject_refs`. A local-check ID is never serialized
as a dangling public subject. Accepted, ranked challenge prose maps into the existing AI-powered
finding summary/detail; it does not add a public result field. The main agent
replies through the existing `respond`/`publish_work` operations and rechecks.

Provider generation and consumption share one owning wire model, `ProviderJudgmentModel` in
`protocol/models.py` (with `ProviderChallengeModel`). The constrained- output JSON Schema sent to
Responses/Chat Completions hosts is generated from that model (`JUDGMENT_JSON_SCHEMA` /
`schemas/findings/provider-judgment-1.1.0.schema.json`, which supersedes the frozen 1.0.0 artifact
by adding per-finding rulings); `normalize_judgment` validates through the
same model before constructing domain `SemanticJudgment`/`ReviewerChallenge`. The schema expresses
closed `FindingKind` and next-step enums, one-to-sixteen citable subject refs with prefix/pattern
and uniqueness, non-empty byte-bounded prose (the provider schema conservatively caps Unicode code
points so every admitted string fits the 4 KiB UTF-8 domain boundary), zero-to-three challenges,
conclusion/challenge coupling via explicit union branches, and `additionalProperties: false`.
Reference order has no semantic meaning: valid refs are ASCII-canonicalized on acceptance; invented
enums, empty prose, duplicate refs, non-citable IDs, and conclusion contradictions are never
normalized into acceptance. The generated schema proves what FinishUP requested, not that every host
enforces it — a nonconforming host response degrades to an invalid AI-powered review result, never a
fabricated pass.

Invalid-result reasons stay exact without retaining provider plaintext: empty/non-JSON or
constrained-schema mismatch → `response_schema_invalid` (`failure_class=response_schema`);
output truncation / provider `incomplete` / Chat Completions `finish_reason=length` →
`response_content_invalid` (`failure_class=response_content`); case-bound post-validation
rejection → `semantic_judgment_rejected`; real transport/deadline timeout → `provider_timeout`.
`incomplete` caused by the output token cap must not be labeled a transport timeout. The public
pair is closed; for `dispatch_kind=external_runtime_oauth` the exact stage is carried separately as
`runtime_evidence.failure_stage` (below) so an operator can tell malformed JSON from a wrong
envelope, an invented enum, duplicate refs, or a conclusion/challenge contradiction without any
retained plaintext. A stage never widens retry: `response_schema_invalid` stays terminal.

Shared types are
`SemanticCase`, `ReviewPacket`, `ReviewAssessment`, `SemanticCaseItem`, `TargetedExcerptRef`,
`ExcerptDigestProvenance`, `ChangeObservation`,
`SemanticJudgment`, `ReviewerChallenge`, `ProviderJudgmentModel`, adapter-returned
`ProviderAttemptProvenance`,
receipt-finalized `SemanticProvenance`, and the single `SemanticStatus`/`SemanticReason` enums
registered in §7. Adapter provenance has no authorization/reservation/receipt IDs and cannot be
published. Final provenance adds exact attempt, dispatch-authority, receipt, commitment, status,
and reason fields only after the terminal privacy receipt is durable; predispatch gaps use the
status/reason pair with no provenance.

`review_item_catalog(items)` and `review_envelope_to_candidate_context(envelope, items, ...)`
(`application.semantic_case`) are the shared catalog/classification projection for explicit checks
and automatic advice. They offer the structural `review-packet` envelope and only catalogued
content as separate categorized candidates. `observation_advice_to_candidate_context(attempt, ...,
review_context_profile, include_finding_prose)` (`application.observation_advice_semantic`)
validates the frozen advice packet through `validate_semantic_evidence_packet`
(`application.observation_advice`), keeps rule metadata and gaps structural, and separates
finding-summary prose. The service passes the effective repository policy's
`review_context_profile` (named in the envelope) and offers finding-summary prose only when
`review_selection_for_delivery(policy).include_finding_prose` (never under `structural`). Both producers use
`assemble_filtered_review_packet` to retain only privacy-approved content. Advice does not invent a
cooperative ledger frontier, source excerpts, or task-check coverage (#1019, ADR-009).

For `dispatch_kind=external_runtime_oauth`, provenance additionally requires one
`RuntimeAttemptEvidence` value. It contains only exact runtime/source/executable/protocol/
capability-cell/capability-evidence-expiry/launcher/config,
disclosed-case/instruction/output-schema/selection/final-output digests, model reasoning
selection, optional safe thread/turn correlation, `chatgpt` auth mode, optional allowlisted plan
type, disclosure/acknowledgement booleans, cleanup classification (`not_started` when no child
existed), an optional closed `failure_stage` (one member of `RUNTIME_FAILURE_STAGES` in
`finishup.domain.findings`, absent on success; the `judgment_*` members mirror the local
validation stages of a completed turn's final answer), and
the literal `upstream_body_observability=unavailable`. Email, credential paths/bytes, raw account
or workspace IDs, prompt/reasoning/event/stderr text, and an asserted upstream body digest are
forbidden. `turn_acknowledged=true` plus ambiguous transport or cleanup maps to
`unavailable/outcome_unknown` and is not retriable.

**Semantic budget profile (issue #571, ADR-006 amendment).** `SemanticBudgetProfile` is the
closed pair `routine | final` (`finishup.ports.semantic_budget`).
`select_semantic_budget_profile(projection, *, final_review=False)` returns `final` when the frozen
projection holds an effective, readable `completion` claim or the check request carries
`final_review: true` (the closing review, issue #976), and `routine` otherwise. The review input
manifest records the selected phase as the optional `review_phase`, and beside its capped
`omitted_item_count` (listed rows, at most 64) the optional `omitted_item_total`
(`MAX_REVIEW_OMISSION_TOTAL`, 1,048,576): every distinct omission before the cap, never fewer than
the rows listed. The selected value is frozen as
`execution.budget_profile` in the `yoetz.semantic-case/2` snapshot. An absent key reads as
`final`, and any other value is `semantic_execution_invalid`. It is exposed to the provider
factory only for the duration of one physical dispatch, and dispatches outside a check see
`final`. For `external_runtime_oauth`, the selected profile maps to the binding's configured
effort and output limit:

- `runtime_evidence.reasoning_effort` is the effort the attempt sent in `turn/start`.
- `sampling_params.max_output_tokens` is the per-check output limit FinishUP enforced on the
  runtime's visible output counters (`output_tokens − reasoning_output_tokens`).
- `selection_sha256` is `canonical_digest({"budget_profile", "model", "output_limit",
  "reasoning_effort"})`. Attempts recorded before #571 committed to
  `{"model", "reasoning_effort"}`.

A snapshot over the limit ends the turn as `output_oversize`. The provenance wire shape is
unchanged.

**Review phase and question set (issue #906).** The same selector names the review phase for every
provider path. `review_question_set(phase)` (`finishup.application.semantic_case`) leads the case
`question_set` with `REVIEW_PHASE_QUESTIONS[phase]` ("Review phase: routine. …" or "Review phase:
final. …"), followed by three phase-independent questions that neither presuppose a defect nor ask
for the agent's next step. The question set was already bound into `case_digest`; its JSON shape is
unchanged. `SEMANTIC_REVIEW_INSTRUCTION` (`finishup.adapters.providers.openai_responses`) is the one
reviewer instruction: the Responses request and the Codex app-server `baseInstructions` send it
verbatim, and `CHAT_COMPLETIONS_INSTRUCTION` is that text plus `CHAT_COMPLETIONS_JSON_SHAPE_SUFFIX`.
Its `PACKET_GAP_GLOSSARY` glosses each packet limit code (capture, selection, redaction, storage)
and omission reason as a packet limit, never an agent defect. `ACCOUNT_GAP_GLOSSARY` glosses the
deterministic codes about the agent's own record (`command_attempt_mismatch`,
`command_attempt_uncorroborated`, `completion_claim_outside_plan`, `completion_plan_not_claimed`,
`completion_scope_declared_none`, `completion_scope_undeclared`) as possible real discrepancies: the
reviewer does not restate the code alone but may challenge what readable material shows.

**Reviewer lenses and grounding (issue #1082, ADR-006 amendment of 2026-10-16).** The instruction
is headed sections joined by blank lines, opening with the role and ending with the reading rules
and gap glossaries. `REVIEWER_LENSES` maps `premise`, `boundaries`, `own_checks`, `method`,
`environment`, `numbers` and `blockers` to their directive text, each with a generic failure
example; `REVIEWER_GROUNDING_RULES` is the tuple of grounding and abstention sentences; both are
exported beside `SEMANTIC_REVIEW_INSTRUCTION` and appear in it verbatim.
`TASK_STATEMENT_REVIEW_INSTRUCTION` opens the "Read the task first" section and now says the
lenses are not the general expectations it forbids. `BLOCKER_REVIEW_INSTRUCTION` and
`ACKNOWLEDGED_REVIEW_INSTRUCTION` open by calling the agent's blocker or acknowledgement its
claim. `tests/fixtures/reviewer_accuracy/n6_cases.json` (`finishup.test.reviewer-accuracy-cases/1`)
is the offline evaluation set; the provider-judgment contract is unchanged.

**Routine frame and the agent's own criteria (issues #1042, #1043; ADR-040 amendment of
2026-10-12).** A routine review judges incomplete work only: an obligation marked resolved or left
unfinished, planned verification not run, a missing or emptied output, a done or ran claim the packet
does not show, an early stop; work not yet started is not a defect. It returns a correctness
concern as `code_defect`, and `validate_semantic_judgment(..., review_phase="routine")` records a
`code_defect` challenge that would mint a new finding as an advisory note instead: its summary and
message are appended to the fenced `review_summary` under the fixed header "Reviewer correctness
notes (advisory and non-blocking: ...)", counted in `SemanticJudgmentReview.advisory_notes`
(returned = accepted + rejected + suppressed + advisory) and logged as
`semantic_challenges_advisory`. No gap is added: the review saw everything and the note is
recorded in full. A re-raise of a recorded finding still folds onto that finding. The final phase is
unchanged. The check passes the phase from the review input manifest (`review_phase`), else from
`select_semantic_budget_profile`. A failure only on probes the agent itself authored beyond the
task's stated scope is the finding kind `agent_criterion_unmet` (priority 2, research-evidence pack,
`finding_recorded` 1.4.0, provider judgment 1.2.0 and every 1.4.0 result wire, added in place on
unreleased versions). `is_limitation_request` is true for it whatever next step the reviewer asked
for, so it reads `limitation_requested` ("to disclose") with next actions `acknowledge` and `repair`:
the agent fixes it (a later check proves it absent) or narrows it with a reasoned `acknowledged`
(`limitation_disclosed`, receipt at best `insufficient_coverage`, listed under "Verification
limits"). Only that answer narrows it: a `finishup-verification-limit` decision neither discloses it
nor marks its obligation `externally_evaluated` (`kernel.limitation`, guard G1). While it is open
the check continues with `work_open_findings`, never `disclose_limitations`, and the CLI text says
fix it, or narrow it with `acknowledged` and a reason. The check also routes a reviewer
`task_requirement_unmet` there when `kernel.review_frame.agent_probe_only` holds. The predicate
holds when every cited work subject is a hook-observed
command run that matches none of the requested commands of the effective, unacknowledged, unblocked
obligations and that the agent did not link to a requested command value (PL6-3:
`kernel.task_facts.agent_linked_run_events` over the frozen prefix, passed to
`validate_semantic_judgment` as `agent_linked_runs`; a linked run is the declared verification, and
an unreadable prefix narrows nothing), at least one such requested command exists, the case carries
none of `planned_verification_failed|not_observed|stale|unobservable|outcome_unknown`, and the
command-identity key is registered. The review summary then says, in fixed words and a count, that
the challenge was recorded as the agent's own criterion (`SemanticJudgmentReview.agent_criteria`,
logged as `semantic_agent_criteria`).

**No review before the first material edit (issue #1046).** A check whose phase is routine, whose
mode, route (`policy`) and capability would dispatch a review, and whose frozen prefix records no
material edit (`kernel.task_facts.material_edit_recorded`: an observed edit or shell write that
counts under ADR-042/045, whether or not its result arrived, so a Codex shell `apply_patch <<EOF`
counts by the files its patch names, or an agent-published `edit` action) while the check-time
capture observed no workspace change, runs the local checks only: `semantic_status` `not_requested`,
`semantic_reason` `deferred_before_first_edit` (1.5.0; a 1.4.0 record may still say
`deterministic_mode` with the same gap), and the standing gap
`semantic_review_deferred_before_first_edit` (rule G7, a semantic-only gap for absence proofs).
There is no supported downgrade over a ledger that holds a projected check-recorded 1.5.0 row.
An older build raises `unknown_event_schema` while opening that row, and the open fails as
`STORAGE_CORRUPT`; it does not skip the row. Unknown schemas stay in the ledger only when they
were written `unknown_unprojected`.
User-facing text says "AI-powered review is on; it starts after your first edit."
Nothing is composed or sent. `semantic_required` included: the deferral is not a failed review, so
the verdict reads from the local checks, never `incomplete_check`. The gap follows the route the
check recorded, like the `semantic_review_not_requested` it rides with (rule G1): disclosed when the
check recorded `semantic_route_required: false`, so the check, status and receipt read as a
`deterministic_only` check on that route would; bounding (`insufficient_coverage`) where review is
required and not current. The deferral never applies to the closing review (`final_review`, or any
completion claim). A resumed check keeps its decision: one already in `semantic_wait` keeps its
review, and one resumed in `ready_to_finalize` reads no fresh capture (a review job its operation
owns means it reviewed; otherwise the frozen prefix decides). Where the deferred check's route
requires review, closure readiness counts it as a use of AI-powered review, so it lists
`closing_review_required`, and while the latest check so deferred an actionable
`semantic_review_not_requested` does not hide it (a routine check would defer again). Where the
check recorded `semantic_route_required: false`, a deferral asks for nothing, like a
`deterministic_only` check on that route.
The older stopped-round skip (`semantic_review_skipped_insufficient_packet`,
`kernel/review_round.py`) is a separate rule the deferral does not change: it can still skip a
closing review that is not `semantic_required`.
The deferral is decided before the review's own admission, so a pre-work check also asks for no
repository grant, disclosure decision or review input, and a missing provider or a policy block is
reported (`not_configured`, `blocked_by_policy`) by the first check after the edit instead.
The CLI, the MCP check text and the receipt's limitations sentence say "AI-powered review
deferred". Readiness is unchanged: the review is still required, so the next check after the
first edit reviews as configured.

`semantic_required` means AI-powered review success is required for a complete verdict, not required
for returning already-computed local truth. Missing approved external/local capability, privacy
block, forbidden/uncertain context, human denial or expiry, provider refusal, timeout, invalid
output, exhausted retry, audit failure, late response, or stale response completes with the frozen
local findings, no AI-powered findings, an exact closed AI-powered review status/reason pair,
weakened coverage, and `verdict=incomplete_check`. It never throws away the local-check result or
substitutes `insufficient_coverage`. Malformed input or storage failure before local-check
durability remains an ordinary operation error.

### Time, IDs, and diagnostics

`ClockPort` has `now_utc() -> datetime` for persisted metadata and `monotonic_seconds() -> float`
for in-process deadline math. `monotonic_seconds()` returns a finite, nonnegative, nondecreasing
process-local sample that is never persisted. The exact frozen semantic value is
`Deadline(expires_at_utc: datetime, monotonic_deadline: float)`, with
`remaining_seconds(now_monotonic: float, /) -> float` and
`expired(now_monotonic: float, /) -> bool`. Remaining time is exactly
`max(0.0, monotonic_deadline - now_monotonic)` and equality is expired. Both methods require the
current sample explicitly and never read ambient time; `expires_at_utc` is diagnostic only and
cannot affect the budget. Deadlines never cross a process restart. `format_rfc3339_millis` and
`parse_rfc3339_millis`, and `add_utc_milliseconds` are pure helpers owned by
`domain/values.py`, not a clock adapter.

`IdPort.new(kind: IdKind) -> str` is the only application/kernel-facing random ID source.

`DiagnosticsPort.record(StartupCheckResult)` accepts only bounded structural results.
`StartupCheckArea` is `runtime`, `package`, `resources`, `path`, `service_control`,
`service_lifecycle`, `sqlite_build`, `sqlite_schema`, `ownership`, `ledger`, `objects`, `keys`,
`vault`, `secret_memory`, `projection`, `privacy_policy`, `egress_gateway`, or `provider`;
`StartupCheckOutcome` is `ok`, `degraded`, or `blocked`;
`RuntimeCapability` is `structural_read`, `payload_read`, `write`, or `semantic`.
`evaluate_startup_gate(results) -> StartupGateReport` is pure and no write-capable application is
exposed until the required gate passes.

Maintenance operation evidence is deliberately separate: `MaintenanceDiagnostic` is the frozen,
path-free record of one `backup|restore|migration` `preview|execute` observation, and
`MaintenanceDiagnosticSink.record_maintenance` is its only sink. It carries only closed outcome,
request/optional task identity, plan/result digests, migration versions, count, duration, bounded
reason, and observed time. It is never accepted by `DiagnosticsPort.record`, never passed to
`evaluate_startup_gate`, and cannot change runtime capabilities.

v0.1 exception diagnostics contain only a generated correlation ID plus bounded component,
operation, outcome, and reason identities. Exception messages, locals, source excerpts, paths, and
tracebacks are neither emitted nor captured in plaintext or encrypted form. A future encrypted
diagnostic artifact is a separate privacy-authorized, schema/retention/encryption-reviewed feature;
it cannot be introduced as a logging mode or support-bundle switch.

For v0.1, an unavailable or locked vault fails closed for all six task workflow operations,
including task `status`; key-independent `version`/help and the bounded `ServiceStatus` control
surface remain available. A future structural task-status mode requires its own public schema and
threat review rather than an implicit partial read.

### Structural subject-state capture

`SubjectStateCapturePort.capture(command: SubjectStateCaptureCommand) ->
SubjectStateCaptureResult` owns the optional local effect that produces comparable
`SubjectStateRef` digests. Shared types are `SubjectStateCaptureCommand`,
`SubjectStateCaptureResult`, `SubjectStateStatus`, `SubjectStateFormat`,
`SubjectStateLimitation`, `SubjectStateBound`, `SubjectStateLimitDetail`, and the
non-serializable `LocalWorkspaceHandle`. When a capture fails on a file-count bound, the result's
`limit_detail` names which bound tripped (`unsafe_tree_entries` or `untracked_file_count`) with
the observed count and the limit — integers only, never content. The safety walk that feeds the
`unsafe_tree_entries` bound skips the root `.git`'s internals and gitignore-excluded subtrees, so
its count approximates the population capture actually hashes (#243).

v0.1 format is `git_structural_v1`, implemented by `GitSubjectStateAdapter` under ADR-011. A
complete result contains both `tree_digest` and `diff_digest`; every partial, changing, unsafe,
unsupported, or over-limit capture returns no subject state and explicit closed limitations. The
port returns no repository content, path, filename, branch, remote, Git output, or component
digest. It is client-local support used before ordinary publication, not a seventh MCP/workflow
operation, not service-owned ambient inspection, and not an `ArtifactInspectionPort`. The adapter
also exposes its hardened runner and root fences (`discover_workspace_root`,
`local_workspace_root`, `run_read_only_git`) to the ADR-031 check-time change capture; that sibling
returns content, under its own decision, and this port still returns none.

The closed limitation values are `not_git`, `unsafe_root`, `submodule_present`,
`symlink_unsupported`, `object_format_unsupported`, `git_config_limit_exceeded`,
`read_limit_exceeded`, `file_limit_exceeded`, `git_failed`, and `input_changed`. The Git config
prefix scan has its own 1 MiB bound; it never reuses the subprocess-stderr cap. The state-capture
CLI surfaces only one of these closed tokens, with bounded remediation where one is registered;
unrecognized exception text remains `invalid_request` and is never echoed.

Publishing a captured digest preserves the actual publication channel and authorship assurance. A
complete capture may support `content_digest` evidence immutability, but never earns
`harness_observed`, `hook_observed`, `artifact_verified`, or `independently_reproduced` by itself.

### Bundle runtime and exact routing

`BundleRuntimePort` methods are:

- `provision_start(command: BundleProvisionCommand) -> TaskRuntime`;
- `route(command: RouteCommand) -> TaskRuntime`;
- `verify_start(runtime, expectation: StartMilestoneExpectation) -> StartCompletionEvidence`;
- `release(runtime) -> None`;
- `close() -> None`.

Shared types are `ServiceRuntimeContext`, `RouteAccess`, `RouteCommand`, `BundleProvisionMode`,
`BundleProvisionCommand`, `OwnershipFence`, `TaskRuntime`,
`StartMilestone`, `StartMilestoneExpectation`, and `StartCompletionEvidence`. Runtime scope kinds
are removed: only the ready service constructs or receives this port. Route access is
`structural_read`, `payload_read`, `write`, `import_review`, or `maintenance`. A task runtime
contains only validated task/session/writer identity, admitted capability/version/fence values,
and task-scoped
`LedgerPort`, `ObjectStorePort`, and `ImporterPort` handles—never a path, SQLite connection, or raw
key. Exact catalog routing and owner-generation fencing are mandatory; cwd/fuzzy/path fallback is
forbidden.

A `structural_read` lease carries no payload authority. A cold structural open loads no bundle
keys, and the ready composition's object opener refuses it. A lease on a warm entry that was opened
for payload or write access exposes only record envelopes, with `payload` absent, and the
frontier; it exposes no object read and no payload-derived projection read. Code that reads a typed
payload field routes `payload_read`. This includes coordination inputs, obligation ownership, and
project advisory finding reads of an admitted sibling. It keeps a warm and a cold cache entry
behaviorally identical (#839).

`RuntimeCachePolicy` makes multiplicity bounds explicit: `max_open_bundle_tasks` covers warm
entries plus in-flight openings, `max_opening_tasks` bounds concurrent open work, and
`max_writer_connections` bounds task-bundle writer authorities. `max_pending_leases_per_task`
prevents one task from filling the validation window. A ready composition may provide a typed
`RuntimeScope` resolver and repository/project limits; a scope refusal is retryable `BUNDLE_BUSY`
with bounded `count` and `limit` details. The cache retains task ownership and route-generation
fencing, so an idle writer remains counted until eviction or service close.

`StartCompletionEvidence` proves `bundle_ready`, `lifecycle_committed`, or `result_published`
against the current bundle generation. Catalog completion consumes that evidence while the same
authoritative process holds the fence. This generation-fenced verification-then-catalog-commit is
the v0.1 cross-database seam; a stronger atomic proof would require a different storage topology.
At `result_published`, expectation/evidence carry the exact response object ID, envelope digest,
and structural result digest; client-specific privacy projection is outside this seam and is never
stored in the START result object/catalog.

### Codex JSONL importer

`ImporterPort` methods are:

- `capture(value: ImportCaptureInput) -> CapturedImportSource`;
- `reserve_or_resume(command: ImportCommand, source: CapturedImportSource) -> ImportAllocation`;
- `prepare_plan(allocation) -> PreparedImportPlan`;
- `publish_plan(allocation, plan) -> ImportAllocation`;
- `release_lease_for_authorization(allocation) -> None` (prepared, unpublished plans only);
- `next_batch(allocation) -> ImportBatchSelection` (refreshed allocation plus batch or `None`);
- `record_batch(allocation, batch, result: AppendResult) -> ImportAllocation`;
- `prepare_report(allocation, report: EncryptedImportReportRef) -> ImportAllocation`;
- `publish_report(allocation, report: EncryptedImportReportRef,
  evidence_result: AppendResult) -> ImportAllocation`;
- `status(session_id) -> ImportStatusSnapshot`;
- `complete(allocation) -> ImportAllocation`;
- `quarantine(allocation, reason: ImportSafeReason) -> None`.
- `load_review_source(identity_digest: str, through: Frontier) -> ImportReviewSource | None`.

Shared types are `ImportByteSource`, `ImportCaptureInput`, `CapturedImportSource`,
`ImportSourceIdentity`, `ImportCommand`, `ImportAllocation`, `ImportLineOutcome`,
`ImportEventCandidate`, `ImportGap`, `PreparedImportPlan`, `ImportBatch`,
`ImportBatchSelection`, `EncryptedImportReportRef`, `ImportStatusSnapshot`, `ImportReviewSource`,
and `ImportSafeReason`, plus the closed enums
`ImportAllocationOutcome`, `ImportState`, `ImportPhase`, and `ImportLineStatus`.

`ImportPhase` is `source_reserved`, `plan_ready`, `publishing`, `report_ready`,
`report_published`, or `terminal`. `prepare_report` durably pins the exact report object/digest and
canonical final evidence draft (including stable IDs) before that draft is published. If the event
commit succeeds but manifest recording crashes, retry reuses the same report/draft and
`publish_work` replays; it never rebuilds a conflicting object ID under the same event/request IDs.

The structural source identity is
`(task_id, source_commitment, codex_capability_profile_id, mapping_version)`. Supported Codex
versions are an explicit tested set, never a continuous range
inferred between probes. `source_commitment` is the domain-separated bundle-keyed HMAC of exact
source bytes; the raw SHA-256 audit digest remains inside encrypted source/report material. v0.1
captures at most 4 MiB exact JSONL and rejects larger sources; object
chunking is a later format amendment. The v0.1 ordinary import request requires stderr to be
absent: `stderr_present=false`, `stderr_captured_bytes=0`, and `stderr_truncated=false` are exact
constants. `ImportCaptureInput` has no stderr byte source or caller-supplied stderr commitment,
and a legacy/crafted true branch is rejected before capture. A confidential stderr channel is not
part of v0.1. The exact JSONL source remains encrypted.

All planned candidate batches use ordinary `publish_work`. After them, the importer reserves and
publishes one final `evidence_recorded` event (`EvidenceKind.import_report`) that references the
encrypted canonical `ImportReport`; `publish_report` verifies its `AppendResult` before terminal
completion. `status` returns only bounded structural pending/terminal counts, source-identity
digest, phase, and report evidence locator. `check` and `receipt` return retryable
`OPERATION_PENDING` while an import for that session is pending; public `status` discloses it.

Publication is not admitted merely because a request has importer-shaped client metadata. The
first call captures the exact source, prepares and durably stores encrypted batch-plan objects,
creates one `import_publication` pending consent with a content-free
`yoetz.import-publication-preview/1`, releases the import lease, and returns non-retryable
`PRIVACY_AUTHORITY_REQUIRED`. The preview binds the source identity, capture-manifest commitment,
plan digest, task/session/writer, capability profile digest and version, mapping version,
structural bounds, and fixed source/line/excerpt/batch limits. It explicitly says complete
transcript inclusion, reasoning inclusion, and reviewer-egress widening are false.

Approval creates an owner-only internal authorization record, never a bearer value or CLI/MCP
argument. Replaying the same import request reacquires its lease and activates the grant only in
that execution context. Before each append the importer binds admission to the next persisted
batch or report request ID and its exact ordered event IDs; ordinary `publish_work` additionally
checks the bound session/writer and the fixed importer actor/client/channel metadata, and admits
that publication only once. The record stays available across restart until terminal import
completion, then is consumed. Denial creates no record. Any source, manifest, plan, target,
profile/version, mapping-version, or limit change produces another target digest and cannot reuse
the decision. This is a local intake permission and does not authorize AI-powered review or other
egress.

Importer publication identity is permanently reserved in both directions: the publishing
writer/request pair and the source/ordinal pair are unique. Ordinals `0..batch_count-1` name
batches and ordinal `batch_count` names the final report. Plan publication and ledger append both
verify these reservations inside their authoritative transaction; terminal transitions never
delete them. The closed quarantine registry contains the six source/object/plan/batch/report/phase
contradiction codes plus `import_commit_state_ambiguous`; malformed or unknown input is a gap.

A job belongs to the writer that published it. `reserve_or_resume` decides that boundary before it
reads job state, so only the stored `publishing_writer_id` can resume a pending job or replay a
terminal one; any other writer submitting the same source bytes gets non-retryable
`INVALID_REQUEST` and never sees the owner's report, request id, or report locator, and its own
request id stays unaliased. Both adapters decide this at the same point.

Application import/review owns frozen `ImportCodexJsonlRequest`, `ImportReportInternal`,
`ReviewRequest`, `ReviewCounts`, and `ReviewInternal`. The internal results contain no
`privacy_projection` and perform no disclosure call; the central application facade projects the
support result exactly once per client and supplies the public schema field. No artifact-inspection
port exists in v0.1. Review compares only recorded/captured evidence at a
frozen frontier. Live Git/shell/filesystem inspection requires a later consent/root/symlink/
submodule/redaction ADR and a separate port.

`ImporterPort` is **batch JSONL import only**. Live Codex observation is owned by
`ObservationPort` below. The two surfaces may reuse mapping-version and gap-code vocabulary; they
do not share allocation, cursor, consent, or advice state, and import never earns `hook_observed`.

### Live Codex observation and advice

`ObservationPort` is the local-control boundary for first-party Codex live observation. It is not
an MCP tool and does not extend the six-operation public workflow. Methods are:

- `ingest(envelope: ObservationEnvelope) -> ObservationIngestResult`;
- `status(query: ObservationStatusQuery) -> ObservationStatus`;
- `pause(command: ObservationControlCommand) -> ObservationStatus`;
- `resume(command: ObservationControlCommand) -> ObservationStatus`;
- `revoke(command: ObservationRevokeCommand) -> ObservationStatus`.

Ledger materialization uses ADR-022's derived harness writer identity:
`observation_writer_id(task_id, session_id)` applies mapping version `obs-writer/1.0.0` and role
`observation`, and admission unions that id with writers from completed starts without fabricating a
start operation. Observation-derived lifecycle records are evidence under that writer, not claims
on the cooperative agent's behalf. Materialization emits `evidence_recorded` unless the structural
payload itself carries an explicitly admitted `claim_kind`. Mapping `obs-ledger/1.4.0` additionally
materializes trusted eligible capture manifests as `evidence_recorded/1.2.0`. Mapping
`obs-ledger/1.6.0` makes the idempotent operation digest task-scoped (task, canonical logical
identity, draft-role tuple, mapping version; no session or writer), matching the stable event ids
it commits, and the coordinator resolves it task-wide through `lookup_task_operation` so a
workflow reattach that rotates the session and writer still replays the committed operation
(issue #560). Its canonical identity includes the source lane, host session commitment, and source
generation, so a reused call id cannot alias another session or generation; Codex hook and
session-stream copies in the same lane still coalesce. Legacy 1.5/1.4/1.3/1.2 operation identities
remain replay-only upgrade candidates with their historical identity shape.

Shared closed types:

- `ObservationSource` — exactly `claude_hook | codex_hook | codex_session_stream | cursor_hook`. Hooks
  are the primary low-latency source; session-stream reconciliation is selective and secondary.
  Bundle migration `0009` rebuilds the `observation_cursors` and `observation_events` tables so
  their source CHECK admits that same closed set; a bundle still at schema 8 refuses every
  non-Codex source at the store, which is why the enum and the DDL are locked together by a test
  over every member (issue #576).
- `ObservationEnvelope` — Codex session identity (commitment, never raw path), event kind (exact
  closed identifier from the capability cell, or an opaque unsupported token), stable source
  identity, `ObservationCursor`, receipt time, bounded allowlisted structural payload, content-
  object references (encrypted object IDs/commitments only), and gap codes.
  Host hook profiles also declare a pairing contract: `pairing_mode` is `paired` or `post_only`,
  and `correlation_kind` is `tool_call_id`, `generation_id`, or `none`. Claude Code and Cursor's
  installed legacy hook profiles are post-only; Claude may use a retained `tool_use_id`, while
  Cursor's `generation_id` is metadata only and never a tool identity. Codex remains paired even
  when an input tries to carry a different marker. The source-qualified Codex hook content arm is
  profileless and is selected by `codex_hook` source identity plus active observation consent
  authority/generation; it never borrows a Claude/Cursor content profile. The source plus exact
  capability-profile table is
  authoritative for historical envelopes and omitted host-version fields; a future paired
  Claude/Cursor profile must register an exact profile cell. Pairing state is admitted under one
  local-store lock with deduplication, so a duplicate cannot consume a pre-event and a concurrent
  second post remains an explicit orphan.
- `ObservationContentChunk` — ordinary-control-only bounded visible content carrying exact
  `content_kind`, correlation identity, source commitment, media type, part index/count, redaction
  flag, and bytes. At most 16 chunks and 700,000 aggregate input bytes keep the request below the
  ordinary 1 MiB control-frame cap; each assembled encrypted object remains below 4 MiB.
- `ObservationContentManifest` — trusted-local binding from an encrypted captured-object envelope
  to the SHA-256 digest and byte count of its secret-scanned inner bytes. A row created before
  migration 0008 has NULL bindings and cannot earn capture provenance by inference.
- `ObservationCaptureTicket` — metadata-only service-side handoff for Claude Code and Cursor
  native content and the source-qualified profileless Codex hook arm. It binds the encrypted
  object IDs and complete expected content groups/parts to the exact workspace/task, FinishUP and
  host sessions, source cursor/generation, selected native profile when applicable, and
  content-authority generation. For `codex_hook`, active consent authority/generation, workspace
  commitment, source identity/commitment, tool-call correlation, object kinds, and object/content
  digests are also fenced; no Codex content profile is inferred. `staging` means the ticket is
  reserved before object publication; `pending` means its complete encrypted manifest set is durable
  and awaits
  the structural FIFO ingest; `revoked` is a retained ABA-protection tombstone. The ticket never
  carries plaintext or a local spool path.
- `ObservationInspectionSnapshot` — one current subject-state/changed-path selection with optional
  independently encrypted facts and bounded-excerpt objects, each carrying its own inner-content
  digest and byte count. Durable redaction/truncation flags preserve weakening without reopening
  the object.
- `ObservationCursor` — source generation, byte/event position, last source commitment, and
  mapping version. Codex session-stream cursors use `codex-obs-stream/1.4.0` (rollout JSONL
  grammar, paired with the profile id the generation's header admitted — an exact certified
  profile or `codex-rollout-jsonl/compatible/v1`; a `1.3.0` or older cursor is mapping-reset and
  replays from its header, so a stream durably refused under the exact-version policy is read
  once under the structural policy with no duplicate publication, issue #656).
  Cursors are crash-stable and generation-fenced. A private HMAC of the source
  device/inode detects same-or-larger file replacement across reconcile processes; ordinary safe
  integers retain their numeric encoding and larger filesystem values use a bounded hexadecimal
  representation before canonical encoding. Call-id/tool
  pairing and outbox dedup are fenced by the resulting source generation, and legacy unfenced
  pairing state is discarded. For a paired output the same-generation originating call's tool name
  is authoritative; a conflicting output self-name is overwritten and records `dedup_conflict`
  rather than selecting a different action family. Rollout privacy filtering parses the valid JSON
  tree first and then redacts decoded string keys and values, preserving structural punctuation;
  any redaction-created duplicate key is rejected instead of silently merging fields.
- `ObservationGapCode` — closed coverage tokens. `payload_too_large` is one host hook event whose
  body exceeded `MAX_HOOK_STDIN_BYTES` and was not admitted as a structural row. Every host stops
  there when the body does not fit `MAX_HOOK_SKIM_BYTES` or the skim cannot validate a complete
  document (Codex and Claude Code skim too since tb4n1 B5). It is not `truncated_payload`, which is an
  admitted payload clipped after parsing. Nothing about such an event is retained beyond the host
  that ran it and the hook name that host named on its own command line, so it mints no structural
  row and binds to the workspace through the command-line locator alone. A Cursor body parsed
  inside the skim cap that still yields no row (no session, no resolvable workspace, an ambiguous
  session, or an unknown event) records the same gap; the ordinary profile's deliberate
  `afterMCPExecution` skip does not, because its paired `postToolUse` owns the call.
  `payload_content_omitted` is the case that did validate on any host but still did not fit the
  trusted cap without its image bytes: the structural row keeps the closed identity and an empty
  content-reference list, and coverage must not treat the omitted native bytes as captured. A
  FinishUP-owned MCP tool's identity row records neither gap, because its content is never captured. `session_superseded` is a mapped host session
  whose FinishUP route was retired and whose successor binding could not be followed; it is never
  `ledger_rejected` and never `mapping_missing` (issue #577). `unsupported_event` is an admitted profile with
  an unrecognized wrapper or nested item, or a known wrapper with an incompatible payload shape
  (`wrapper_shape_unsupported`); `unsupported_format` is a structurally refused surface (exec
  JSONL, a header that is not `session_meta`, a non-object payload, a non-string `cli_version`,
  an absent/unknown `history_mode`, or compressed `rollout-*.jsonl.zst` that the hook pass does
  not decompress). The `cli_version` itself is diagnostic provenance, never a refusal (issue
  #656): an exactly proven release (`SUPPORTED_ROLLOUT_PROFILES`, currently `0.148.0` and
  `0.150.1`) admits under its certified profile with provenance `exact`; any other release admits
  under the structural compatibility profile `codex-rollout-jsonl/compatible/v1` (union
  vocabulary) with provenance `structural`. The reconcile result names a closed `admission` state
  (`structurally_supported`, `partially_understood`, `incompatible`, `unadmitted`), its
  `admission_provenance`, and the bounded `admission_reasons` tokens; none of these is host
  support. A refused header holds for the whole source generation: bytes are consumed, no event
  is admitted, and the cursor is kept. When exact-session `.jsonl` and `.jsonl.zst` siblings both
  exist, the admitted uncompressed file wins; compressed-only remains explicitly unsupported.
  Every string semantic type present at `payload.type` and nested `payload.item.type` must belong
  to the admitted profile before a nested item is selected; one known field cannot mask an unknown
  peer. Unknown semantics never infer success.
  A rollout line above the admitted 1 MiB line bound enters a private authenticated continuation
  state bound to the session, source generation, and source identity. Each later reconcile scans at
  most one 256 KiB chunk; its byte cursor may advance within the oversized line while the event
  ordinal stays fixed. The terminator advances once as opaque `unsupported_event` evidence, using a
  domain-separated commitment over the bounded prefix commitment and exact source span, so later
  records remain reachable without an unbounded hook pass. Until then the tail remains pending as
  `truncated_payload`. The marker contains no source bytes, and an invalid or transplanted marker
  starts a new generation from profile admission rather than authorizing a skip. An ordinary
  unterminated final line (Codex still writing it) is held and re-read once its newline lands; it
  lost nothing, so it is not `truncated_payload` (issue #1041). The compatibility profile also
  admits the `event_msg.item_completed` item `HookPrompt` (a Stop hook's continuation prompt,
  Codex 0.159.3) as bookkeeping: no structural field is read from it and it pairs with nothing.
- `ObservationStatus` — lifecycle `active|degraded|stale|stopped`, source coverage, last
  observation, lag, currently true gaps, unsupported events, and the current `AdviceSnapshot`
  frontier identity. Per-code first/last-seen history is retained separately and does not make a
  healed mapping, cursor, quarantine, or outbox condition remain current forever.
- `HookSpool` — private legacy-host ingress only: `append(workspace, event, structural payload)`
  makes one fsync'd bounded record keyed by a workspace HMAC; `claim(workspace commitment)` uses
  rename fencing and exposes records to the READY service. A stable spool UUID enters source
  identity, so crash replay is at-least-once and normal local ingest deduplicates it. Pending spool
  work projects `source_lag`; it is not an acknowledged observation.
- `AdviceSnapshot` — ranked `AdviceItem` values (finding id, local rule code, priority,
  summary, evidence-linked detail, next action, evidence refs, coverage, freshness) plus exact
  evidence basis, confidence/coverage, recommended next action, freshness, and suppression
  identity. It surfaces through nonblocking observation/
  integration hooks and through ordinary public `status` (and existing finding/coverage machinery);
  it is never a seventh MCP tool. Local observation-advice policies derive the snapshot
  from retained envelopes (and optional inspect/approved-check/composition facts) even with zero
  cooperative FinishUP MCP publications. Optional AI-powered advice is additive only, through the
  privacy gateway, over minimized approved packets. Local finding identity is condition-
  scoped over policy, kind, rule code, and rule-specific cause; rolling or accumulating evidence
  refs never participate in identity. Envelope-linked candidates use only their mapped ledger
  events as the first durable subject anchors, while standing session conditions use the stable
  lifecycle event. Once a readable condition finding exists, later evidence-window or frontier
  changes update the observation snapshot and coverage/gap state without appending another
  `finding_recorded` event. When the rule-specific cause is one host tool call, that cause is the
  logical call — source, session commitment, source generation, and the admitted
  `correlation_id`/`tool_call_id`, or the envelope's source identity when neither is observed —
  and never the observed phase or event position. `edit_after_successful_check` therefore reports
  one condition for a paired `PreToolUse`/`PostToolUse` edit while retaining both phases in its
  evidence refs; a post-only profile reports its single observed phase, two calls remain two
  conditions, and a call id reused across a source, session, or generation boundary stays
  separate.
  The local verification baseline is typed: only a current `passed` approved-check fact,
  or an explicit success from a dedicated verification tool (`test`, `pytest`, `cargo_test`,
  `npm_test`, `uv_run_pytest`), establishes or advances it. A successful generic host shell
  (`shell`, `Bash`, `bash`) and any routine read prove a tool outcome, never a check, so they
  neither create a baseline, nor move one past a later edit, nor satisfy
  `completion_without_verification` or the live arm of `static_test_for_live_claim`. Check
  identity is never inferred from command text or a host-supplied `action` label. The failed and
  unresolved-command rules continue to read every command-bearing tool including generic shells.
  Snapshot construction is session-scoped: a mapped session's snapshot is built from that
  session's own retained envelopes and session-scoped lifecycle/gap health (resolved from the
  ingest envelope's session commitment or the durable workspace session route), never from every
  retained workspace envelope. The workspace-wide aggregate remains the operator surface
  (`finishup observe status`) and the source of deliberately workspace-standing machine conditions;
  it is not an input to a mapped task snapshot (ADR-022 decision 14).
  Hook-channel delivery is relevance-scoped: task-scoped conditions come from the mapped FinishUP
  session snapshot when one exists, otherwise from the current Codex session's retained envelopes.
  The workspace-wide snapshot is not a fallback for task-scoped work. Deliberately workspace-
  standing machine conditions remain deliverable from that workspace snapshot at the documented
  session-boundary cadence (`SessionStart` and `Stop`). The agent-visible context carries only
  the bounded rule, action, and evidence token; deciding whether the advice belongs to the
  current target never requires inspecting FinishUP storage. The snapshot's
  `recommended_next_action` remains the kernel token, including `refresh_observation`. Hook
  `additionalContext` maps that machine-condition token to a host-shell next step (`finishup observe
  status`) rather than naming a nonexistent MCP tool or CLI verb. Codex hook stdout is
  event-specific: `SessionStart` / `PostToolUse` / `UserPromptSubmit` emit
  `hookSpecificOutput.additionalContext`; `Stop` emits `decision: block` plus `reason` (Codex's
  hooks reference, re-read 2026-08-28, still gives Stop / SubagentStop only the common output fields
  plus `decision`/`reason`, and documents `decision: block` as a continuation prompt;
  `stop_hook_active` plus delivery identity are the loop guard); `SessionEnd` always emits `{}`
  because the host discards its stdout and a peek/commit there would consume undelivered advice.
  Claude Code hook stdout uses `hookSpecificOutput.additionalContext` for every advice-bearing
  event in the installed profile: `SessionStart`, `PostToolUse`, `PostToolUseFailure`, and `Stop`.
  The raw host event is retained in `hookEventName` even though `PostToolUseFailure` shares FinishUP's
  internal `PostToolUse` advice cadence. At `Stop`, Claude Code documents `additionalContext` as
  non-error feedback that continues through the same loop guard; the Claude ingress therefore
  never emits `decision: block`, and its `SessionEnd` emits `{}`. The renderer also knows Claude's
  `SubagentStart` / `SubagentStop` output shapes. The conservative 0.2 structural profile does not
  advertise either event; the 0.3 capability profile may add them only with an exact reviewed cell
  and native evidence. An observed neighboring Claude version never upgrades that profile claim.
  Cursor has a separate native contract: raw `sessionStart` emits `additional_context`; raw `stop`
  advice is disabled because `followup_message` auto-submits a user message; and `afterFileEdit`,
  `afterMCPExecution`, and `sessionEnd` emit `{}`. Cursor leases and commits advice only for a
  nonempty `sessionStart` object after its bytes are written successfully. Output-less events never
  lease or consume advice. No hook on any host delivers a frontier-motion notice: every recorded
  notice describes observation-authored motion, which leaves held frontiers admissible (issue #915). Provider-repair advice is standing advice and
  uses only the session-boundary channels (#844). Service composition sets `semantic_configured`
  only when verification is not disabled, a provider endpoint is bound, network egress is permitted,
  and an LLM inference channel is enabled. The verification default, including absent config, is not
  that intent. A private or no-egress install, an install with no provider endpoint, and a disabled
  verification setting do not receive `connect_provider`, `renew_provider_sign_in`, or
  `repair_semantic_provider`. When that intent is recorded and the provider is structurally unusable,
  `connect_provider` is still produced, including when no factory id is available
  (`semantic:not_ready`). Codex `SessionStart` places that text in `additionalContext`; Codex `Stop`
  places it in `reason` with `decision: block`. Claude Code places it in `additionalContext` on
  `SessionStart` and `Stop` and still does not emit `decision`. `PostToolUse` does not carry it on
  either host. Cursor places it in `sessionStart` `additional_context`; `stop` still does not submit
  a `followup_message` and does not consume the pending delivery. Advice projection is bounded by the domain
  wire limits: each item carries at most 16 evidence refs and a snapshot carries at most 64 ranked
  findings. The evidence-basis digest still commits to every policy candidate, ref, AI-powered
  review coverage input, and discarded condition. When a projection limit is reached, the visible
  coverage carries `advice_evidence_refs_truncated` or `advice_ranked_findings_truncated`; if those
  markers would exceed the 64-gap coverage bound, `advice_coverage_gaps_truncated` remains visible
  and the complete gap set stays committed in the basis digest. Invalid AI-powered finding ids are
  discarded, invalid AI-powered review text falls back to service-authored safe text, and
  `advice_semantic_output_invalid` weakens coverage. Length-capped AI-powered summaries/details
  carry `advice_semantic_text_truncated` so the clipping is explicit. A host/tool
  `result_status=completed` outcome is not an authored completion claim; completion advice requires
  an explicit `claim_kind` value such as `completion`, `done`, or `finished`. Observation AI-powered
  advice is asynchronous (issue #619): the advice build never calls a provider. The service
  composes it only when `config.models.background_advice_setting` resolves enabled: an unset
  `[observation] semantic_advice_enabled` is on wherever AI-powered review is configured, and an
  explicit value always wins (ADR-006 issue #888; closed reasons `owner_enabled`,
  `default_enabled`, `owner_disabled`, `semantic_review_disabled`, `observation_disabled`,
  shown as `background_advice` by `finishup provider status` and `finishup setup status --next`).
  While it resolves off, startup rediscovery closes rows an earlier service left `pending` as
  `cancelled` / `cancelled` with no provider identity and no provider work.
  `application/observation_advice_semantic.ObservationAdviceSemanticScheduler` looks up or enqueues
  one durable attempt row in `observation_advice_semantic_attempts` (migration 0012), keyed by
  (workspace commitment, FinishUP session, advice-candidate identity; retries of a terminal
  non-success use `<identity>#<generation>` after a backoff, see ADR-006 issue #888), storing the exact scoped
  observation gap tuple and the minimized packet that carries it. Repeated identical builds coalesce
  onto that row; a newer basis for the same session supersedes that session's unattempted pending
  rows (`cancelled` / `superseded`) and keeps every completed row's receipt. At most 16 rows may be
  pending or running per task bundle; the next schedule is recorded `unavailable` / `queue_full`
  with no attempt. A row that is `pending` or `running` adds the coverage gap
  `advice_semantic_pending`; a `failed`, `unavailable`, or `cancelled` row adds
  `advice_semantic_unavailable` with its closed reason (`authorization_missing`,
  `provider_unavailable`, `provider_failed`, `output_invalid`, `queue_full`, `superseded`,
  `cancelled`, `interrupted`). An admission refused by the per-session interval writes no row and
  adds `advice_semantic_deferred` (semantic state `unavailable`). The scheduler first reads live
  provider readiness (review not disabled, an endpoint bound, the machine policy admitting
  `llm_inference` egress, the configured credential present) and route readiness (an ACTIVE task
  route whose repository authority is granted and passes the egress pipeline's static policy leg,
  `semantic_policy_refusal`, for the configured primary binding, the `semantic-review` purpose and
  task scope, read from the policy store without the privacy admission lock; background advice never
  engages a declared fallback endpoint, so readiness reads only the primary; ADR-006 issue #923):
  without both no row
  is written, no provider is contacted, and the snapshot adds `advice_semantic_unavailable` once
  with semantic state `disabled`, never `advice_semantic_pending`; only a completed review of the
  same identity is still reused. When both pass but the effective repository policy needs a human
  preview (`semantic_preview_required`, `application.egress`: profile `confirm_every_request`,
  i.e. the metadata-only recipe, or an LLM channel with `preview_required`), the scheduler's
  `preview_required` probe skips the same way with the typed addon reason `preview_required`: no
  row, revisit, provider identity, backoff or disclosure proposal; the snapshot adds
  `advice_semantic_preview_required` beside `advice_semantic_unavailable` with semantic state
  `disabled` (gap rule G5b, disclosed). A row queued before such a policy change closes at dispatch
  as `unavailable` / `authorization_missing` with no provider identity, and `PrivacyCoordinator`
  refuses an `observation_advice` candidate under such a policy before classification
  (`blocked_by_policy` / `policy_denied`, no proposal, no category approval) (#1019 r2). It
  likewise refuses (`scope_mismatch`) an advice candidate whose envelope names a review-context
  profile other than the effective one, or that offers `finding_summary` prose the effective
  selection excludes (`advice_selection_is_current`, `application.egress`). The dispatch maps a
  `SemanticEgressBlocked` result from its typed reason, never from the configured binding
  (`advice_outcome_for_blocked`, `service.ready_composition`): `outcome_unknown` keeps
  `failed` / `provider_failed` with the provider identity; `policy_denied`, `scope_mismatch`,
  `purpose_not_allowed`, `destination_not_allowed`, `channel_unavailable` and
  `authorization_stale` close `unavailable` / `authorization_missing`; other pre-dispatch refusals
  stay `failed` / `provider_failed`; none of the proven-unsent ones names a provider, and each links
  its privacy receipt or proposal id as `attempt_receipt` (#1019 r3). The MCP `status` advice text
  adds one fixed sentence when the snapshot carries `advice_semantic_preview_required`. Only a `succeeded` row with validated finding ids adds
  `semantic_model_derived`; a succeeded attempt that returned no challenges is an honest receipt and
  no finding.

Independent verification support (local control, not MCP):

- `WorkspaceInspectPort` — descriptor-safe bounded relative-path artifact inspection under a
  consented workspace root; returns digests + capped excerpts; never absolute paths in public
  status. The handle retains an authenticated root directory descriptor for its lifetime.
  Descendants are opened descriptor-relatively with no-follow semantics against that descriptor
  (not by re-resolving the root pathname). In-root symlinks remain readable: targets are resolved
  only within the root, with a bounded chain depth (eight resolutions per requested path); absolute
  targets, climbs above the root, and exhausted depth map to `symlink_escape`. Content whose
  identity or size changes during the read is refused as `read_failed` rather than returned.

- Approved-check runner — executes only commitment-approved argv (`shell=False`, bounded
  time/output, sanitized env, no network unless separately authorized); binds results to the
  observed subject-state digest so later edits stale prior success. On POSIX the child is started
  in a dedicated session/process group, and that group is killed and reaped before any result is
  returned -- on timeout (TERM, then KILL) and equally after a check exits on its own, so a member
  it leaves running never outlives its result. Orphaned descendants are adopted as a child
  subreaper on Linux so a non-reaping PID 1 cannot strand them. A descendant that calls `setsid`
  leaves the group and is not covered; containing that needs a PID namespace. A check that closes
  its own stdout/stderr and keeps running still times out rather than escaping the runner. On
  Windows the launched tree is terminated (`taskkill /T /F`, falling back to TerminateProcess)
  under CREATE_NEW_PROCESS_GROUP console isolation.
- `.finishup/checks.toml` — fixed schema `yoetz.approved-check-policy/1`; raw bytes produce the trust
  digest. The legacy `.yoetz/checks.toml` is read when it is the only policy file; both present
  raises `ObservationCheckPolicyAmbiguous` (`policy_ambiguous`, ADR-048), and status names the file
  used as `policy_file`. Because trust binds to the bytes, a byte-identical move keeps it. Repository content proposes no authority. One trusted-local exact-digest confirmation is
  retained as an encrypted workspace-scoped record. Any byte change is untrusted.
  A missing `.finishup/checks.toml` (or missing `.finishup/`) raises `ObservationCheckPolicyAbsent`, a
  subclass of the `invalid_approved_check_policy` failure, so trust gates still fail closed while
  reporting surfaces distinguish it: `finishup observe checks status` emits `state: not_configured`
  with exit 0, `preview`/`trust`/`run` emit `observation_checks_<op>_failed:policy_not_configured`,
  and the verification worker records no coverage gap. The `not_configured` status object carries
  the same keys as `trusted`/`untrusted` (`policy_digest: null`, `sandbox`, empty
  `executable_checks`, `network_check_state: not_requested`) plus a fixed `note`. Any other policy
  read or parse fault stays `invalid_policy`; workspace or store faults report `unavailable`. Each
  policy failure line is followed by a fixed continuation stating that the route is optional owner
  configuration and never a `finishup-blocker`.
- `ObservationVerificationWorker` plus its repository — one generation-fenced lease per task
  bundle/workspace lane; newer subject digests stale older pending work, identical
  workspace/policy/approval/state tuples are cached, abandoned running work returns to pending,
  and immutable results record whether the post-run state is still current. A repository can have
  multiple task lanes observing the same workspace; their schedulers may run concurrently while
  each lane keeps its own durable job/result rows.
- Each completed approved check materializes a service-owned action/evidence/result graph. The
  captured evidence is a bounded canonical receipt binding approval commitment, result digest,
  output digest/byte count and encrypted output-object identity, subject state before/after, and
  freshness. It uses `evidence_recorded/1.1.0` with `approved_check` provenance; no cooperative
  request can mint that provenance.
- Eligible observation capture is narrower than retention: tool output, selected changed-file bytes,
  and workspace-diff bytes become `observation_captured` immutable evidence. For the
  source-qualified profileless Codex hook arm, those bytes must be explicitly linked to the hook
  event. Session-stream records are a separate source and are excluded from AI-powered review
  selection; tool input and path/locator content are also excluded from AI-powered review selection.
  The Codex hook extractor omits raw tool-input bytes but keeps the encrypted workspace locator
  needed by local inspection and verification; existing structural evidence remains intact (issue
  #623). Visible messages, unsupported visible payloads, and approved-check output do not enter this
  capture path. The repository privacy authority and each provider attempt authorize AI-powered
  review selection independently of local encrypted capture. Inspection fact/excerpt objects
  materialize through their own idempotent evidence operation. Missing, deleted, or pre-0008
  bindings add `content_capture_unavailable`; deliberately excluded retained kinds add
  `content_unselected`; retained redacted bytes add `content_redacted`; and a bounded inspection
  prefix adds `truncated_payload`. Capture never upgrades to `artifact_verified` or
  `independently_reproduced`.
- `ObservationVerificationSupervisor` — ready-lifecycle background owner that wakes on enqueue,
  discovers pending work at startup, drains one serialized check per task/workspace lane through
  the enforcing sandbox, and gives each registered lane one fair round before revisiting a busy
  lane. Unrelated sibling lanes may run concurrently; each lane still has at most one active
  worker lease. It reclaims expired leases and stops before vault/runtime closure. Hook ingest
  never executes approved checks inside the hook RPC budget.
- `ObservationAdviceSemanticSupervisor` / `ObservationAdviceSemanticWorker` — the same shape for
  observation AI-powered advice (issue #619). The coordinator registers a per-workspace drain when
  an advice build leaves `advice_semantic_pending`, and rediscovers pending rows after service
  start. The worker claims one row at a time under a generation-fenced two-minute lease, closes it
  as `unavailable` / `provider_unavailable` with no further work when no provider is usable now
  (#923), otherwise resolves the task route, repository authority, and provider binding at
  dispatch time (never from the READY snapshot), runs the privacy-gated attempt with a 60-second
  deadline, records the closed outcome, and re-runs advice for that workspace. A lease held by a
  previous service generation
  or past its expiry is reclaimed as `pending` and re-attempted; a row reclaimed three times
  terminates as `failed` / `interrupted`. An interrupted, cancelled, or unattempted row is never
  an AI-powered review success. The advice worker is separate from approved-check workers and
  does not execute AI-powered review work inside a hook RPC budget. Pure-ingress hook handlers declare
  `"async": true` only when the exact probed Codex version supports registration; older or unknown
  hosts run them synchronously with the declared 10-second budget so no event is dropped. Handlers
  that return `additionalContext` or a Stop `decision: block` stay synchronous with the same bound,
  and `SessionEnd` keeps the host-clamped 3 seconds for local ingest only; its outbox intent is
  retried by a later hook or the service sweeper, and it is not an advice channel.

  An explicit foreground `start` session rebind has priority over this optional advisory lane. When
  the runtime admits the bounded rebind wait, it signals the registered advice worker to yield. A
  pending row is left pending; an in-flight provider dispatch is cancelled through the worker's
  ordinary cancellation path and recorded as `cancelled` before the drain releases its task
  runtime. That local row is not proof that a physical provider call did not start: if the privacy
  audit consumed authorization, the attempt is terminally `SemanticEgressAttemptUnknown` and is
  never redispatched by this advisory lane. The worker reconciles that case from a shielded,
  bounded finalizer before the cancellation propagates, so the rebind is not held open:
  `PrivacyCoordinator.recover_started_request(request_id)` reports the started attempt for the
  exact request identity the cancelled dispatch minted (a cancelled dispatch never observes the
  prepared case digest), and the cancelled advice row records that provenance as
  `attempt_receipt` (the reconciled egress receipt, else its privacy proposal) plus
  `provider_identity`. When the dispatch minted a provider request and the bounded lookup cannot
  prove its authorization was never consumed (it failed, or timed out behind a foreground check
  holding the privacy admission lock), the row still records `provider_identity` without a receipt
  (#923). A cancelled row naming a provider is a call that may have started with usage unknown;
  a cancelled row naming none sent nothing. Background advice rows retain no token counts. The
  privacy audit owns the disclosure fact. The cancelled packet is never treated as successful, and the resulting
  `advice_semantic_unavailable` coverage remains visible. This cooperative yield applies only to additive observation advice; an explicit
  required semantic check keeps its own operation and recovery contract. The foreground start
  retains its request identity and continues through the existing bounded same-request recovery
  when the runtime becomes available.

Native ordinary-work capture adds a separate, closed profile selection to that workspace consent.
`LocalObservationConsent.content_capture_profiles` is a sorted set containing at most
`claude-code-ordinary-observation-v1` and `cursor-ordinary-observation-v1`; absent legacy fields
mean no native content authorization. `ObservationIngestRequest.content_capture_profile` is an
optional selector in current control-request `2.6.0`, bound to the envelope's host source. The
selector cannot grant capture: ingress requires the active local selection and synchronizes its
bounded profile set to the mapped task store. Structural subscriptions and native content consent
are independent. The source-qualified `codex_hook` capture arm is deliberately profileless: it
requires active observation consent and exact Codex source binding, but does not add a Codex entry
to this ordinary-profile set or accept a Claude/Cursor selector. Profile-free Codex observation
retains its structural contract, while its eligible hook content uses the fenced native handoff
below.

`finishup observe content-enable`, `content-disable`, and `content-status` operate on the same
canonical workspace as observation consent. Their JSON responses and `observe status` identify
`content_capture_scope: ordinary_profiles` and `codex_hook_capture_scope: observation_consent`. The
profile list, effective profile list, and `enabled`/`content_capture_enabled` describe only the
Claude Code and Cursor ordinary profiles. An empty list does not disable profileless Codex hooks,
whose local authority follows observation consent and the runtime gate. Text status names the same
scope. These are configuration facts, not proof of actual capture, successful execution, or
AI-powered review selection; those require evidence and the check/receipt (issue #622). The local
content fence combines a durable per-workspace epoch with a persisted runtime-gate nonce; every real
consent or runtime transition advances it, including pause/resume and off/on ABA cycles, and legacy
state receives a fresh epoch before authority is accepted. Pause, disable, and revoke must fence
retained native content reads and subsequent AI-powered review disclosure as well as future capture.
A structural grant (`LocalObservationStore.grant_consent` with no explicit profile set: Codex setup,
the host-connection and terminal-interface Codex apply, and `finishup observe grant`) over a live,
unrevoked consent continues that consent. It keeps the original `granted_at` and every approved
ordinary profile, and leaves selection and capacity settings untouched. Repeating an effective grant
is not a transition: it neither advances the epoch nor invalidates an in-flight content fence,
read-protection scope, or selection preview (issue #835). A structural grant over paused consent
resumes it exactly as `resume` does. With no prior consent, or after revocation completes its project
fence, a grant starts fresh with no ordinary profile; while that fence is pending, the grant is refused.
Only an explicit profile set, `content-disable`, or revoke removes an arm. The call returns a
`LocalConsentGrant` (`transition`: `granted`, `resumed`, `updated`, or `unchanged`, plus the
resulting consent). The setup report's `observation_consent` block adds that `transition` and the
retained `content_capture_profiles` beside the existing `outcome: granted`. `observe grant` prints
`observation_content_capture_kept:<profiles>` when it kept an arm.
A task-store snapshot is not independent authority after a local consent change. Selection into an
AI-powered review case additionally requires authenticated captured-object provenance, case
membership, source/session/phase binding, and the effective privacy selection. Captured bytes remain
bounded advisory evidence; they do not prove that a command passed, a file was independently
inspected, or a reviewer acted on the bytes.

The repository privacy commitment on a `TaskRoute` is an egress-policy key, not an observation
workspace key. AI-powered review composition resolves the observation workspace only from the
durable workspace-to-FinishUP-session route, verifies that route's task matches the exact runtime task,
and rechecks that binding before disclosure. An inactive historical route is usable only for the
same task. An absent, ambiguous, or mismatched route leaves captured content unavailable; the
privacy commitment cannot substitute for the observation workspace. The coordinator records the
accepted completed-tool session route before optional verification policy setup. Native
captured-content selection does not require an approved-check policy.

Observation consent is one workspace-level confirmation recorded as a private workspace commitment.
Consent, status, pause, resume, revoke, setup probes, and hook ingress all canonicalize an explicit
Git subdirectory to the same nearest safe Git project root; a non-Git directory remains its exact
safe locator. A safe project root is the running user's own directory that no other account can
write or, for a non-root user, a root-owned directory that no other account can write or that is
sticky (ADR-007, 2026-10-14); anything FinishUP writes inside it must still be the user's own. The
nearest `.git` (directory or worktree file) ends the walk when the user owns it, or, for a non-root
user, when root owns it, no other account can write it, and it is a directory or a single-link
regular file (`config.foreign_write.superuser_checkout_marker`; an image built as root): that
directory is the locator, judged by the same rule and used as a plain directory, since Git capture
refuses another owner's worktree; a `.git` another non-root account owns, others can write, or a
hard-linked root file fails the locator closed. There is no ancestor-commitment fallback. A legacy grant recorded against an exact
Git subdirectory does not authorize its ancestor and must be explicitly granted again.
The normalized locator is authenticated encrypted content; plaintext keeps only commitment and
object ID. Revocation disables/removes the active locator and trust binding while retaining already
encrypted evidence. The service first records a bounded private revocation token, then advances
every active project generation selected by the affected task routes; queued detections from the
older generation are permanently ineligible for delivery. An interrupted fence remains pending
and blocks re-consent until recovery completes, so a later grant cannot revive an old detection.
Visible task messages, tool input/result, task-linked terminal output,
changed-file/diff material, approved-check output, lifecycle, and readiness facts may be captured.
Hidden reasoning, system/platform/developer prompts, credentials, detected secrets, unrelated files,
and untethered logs are excluded before storage. Every byte that reaches encrypted observation
persistence passes `prepare_persisted_plaintext`: high-confidence secret spans (known credential
shapes, private-key markers, URI passwords) are redacted in memory before encoding, matches persist
only redaction metadata, and scanner failure, high-confidence finding-capacity exhaustion, or a
canary match records `content_capture_unavailable` and stores no excerpt or approved-check output
object. Heuristic-only assignment matches are kept as captured in the encrypted local store, where
local and deterministic checks may read them, and are redacted only at egress (issue #982); a
chunk or excerpt is marked `redacted` only when its bytes were actually replaced. SQLite/envelopes
retain only encrypted object IDs, commitments, classifications, sizes, and relations.
Vault/service failure records `content_capture_unavailable` and no plaintext spool.
Unrecognized visible events accept an opaque stable envelope plus encrypted content and
`unsupported_event`; a session-stream file that is the wrong grammar, an untested `cli_version`,
or a compressed `.jsonl.zst` rollout records `unsupported_format` instead. Unknown semantics never
infer success.

Native service-side staging and FIFO handoff (ADR-003 and ADR-022 decision 22) applies to the
Claude Code and Cursor ordinary native profiles and to the source-qualified profileless `codex_hook`
arm. A capture-only control request enters a separate bounded lane, reserves an
`ObservationCaptureTicket`. Global observation disable retires matching unfinished tickets for
Codex, Claude Code, and Cursor through the authenticated session/workspace cleanup path. Repeated
cleanup is idempotent; a later consent generation cannot revive a revoked ticket. Session-stream
requests do not enter this cleanup lane, and ticket retirement does not delete historical content
(issue #624). The enabled capture lane reserves an
`ObservationCaptureTicket`, secret-scans and encrypts eligible chunks, publishes the objects and
manifests, and marks the ticket pending before the host's structural envelope advances the FIFO
cursor. For Codex, selection additionally requires the reviewed cursor mapping
`codex-obs-hook/1.0.0`. Unknown, future, and other-source mappings are rejected before resolving or
opening a captured object; no legacy mapping is implicitly accepted (issue #621).
Active observation consent selects the profileless arm; no Claude/Cursor content
profile is accepted. The structural retry must present the same exact source/session/cursor
identity, workspace/task binding, tool-call correlation, and original source and authority
generations, and the service accepts the ticket only when every expected content group and part is
present, readable, and digest-bound. A complete retry binds the existing manifests to the envelope
and removes the ticket after the ledger append; it never remints an equivalent capture.

Native chunks and recovered manifests must also match the envelope's source commitment and its
admitted host correlation or native source/label identity before they can become captured evidence.
For `codex_hook`, only explicitly linked tool output, selected changed-file/code bytes, and
workspace-diff bytes are eligible for AI-powered review selection. Session-stream records remain
outside this native handoff and are excluded from AI-powered review selection. Tool input and
path/locator content are excluded from AI-powered review selection too. The Codex hook extractor
retains complete post-tool command input locally only as authenticated
eligibility context for verification-output follow-ups (#1079 F1); other raw `TOOL_INPUT` stays
omitted. Command input is excluded from provider excerpts and structural records. It keeps the
encrypted `WORKSPACE_LOCATOR` from SessionStart because the local inspection and verification
scheduler opens that locator to resolve the workspace and its approved-check policy. Removing it
would break a supported local consumer. Neither kind becomes AI-powered review content; ordinary
Claude/Cursor profile contracts remain unchanged (issue #623). Missing or conflicting native binding
metadata retains `content_capture_unavailable`, including when materialization is called
independently of AI-powered review. A terminal structural rejection retires only its exact admitted
capture ticket so it cannot permanently block later checks; retryable coordination retains that
ticket for the next attempt.

Only the structural row a handoff was staged for can consume it, so that row's delivery also
retires a handoff it leaves behind (issue #836). After the row commits without consuming its
matched ticket (content fenced, blocked, or unauthorized at delivery), or after a terminal refusal
(`ledger_rejected`, `dedup_conflict`, `session_superseded`, `observation_storage_corrupt`, or a
terminal store refusal), the coordinator re-reads the durable ticket under the capture lock and
tombstones it only when its task, host session, source, source identity, and cursor match that row.
The same step retires a handoff that a capture-only request staged while the row was already past
its capture fence. A capture-only request whose structural envelope the task store has already
accepted, and which no outbox row or selected input can deliver again, stages nothing and returns
`content_capture_unavailable` with that coverage gap; a row still queued after an interrupted
delivery can still receive a handoff and consume it on retry. A hook drain delivers every mapped
lane in the shared workspace, but sends its content profile only with rows from its own host: a
Claude Code or Cursor hook delivers a queued Codex or other-host row without a profile, and the
service resolves that row's profile from its own ticket, instead of refusing it as the terminal
`content_capture_profile_mismatch`.

Every retirement of a handoff (any `CaptureHandoffRetirementReason`) also appends one
service-authenticated marker to the ticket's own task ledger, keyed by the ticket identity, whose
coverage carries `capture_handoff_retired` (issue #1019), including a ticket a terminal store
refusal retires. The marker and its fixed sentence claim only that the captured content is not
available; for a refused or quarantined row the call's own record may be missing too, and its own
codes disclose that. The marker is appended before the ticket is
tombstoned: a retryable or unexpected append failure leaves the ticket pending, and the next
reconciliation pass (READY sweep or check preflight) publishes it and only then retires the ticket,
counting the loss once. A ledger that terminally refuses the marker (a non-retryable typed refusal,
an operation conflict, or a route without a writer) can never hold it, so that retirement proceeds
without the marker and the refusal is recorded in service diagnostics. The marker names the closed retirement
reason only, never a path or content, and another task never receives it. The code is a standing
limitation with a fixed sentence: deterministic proof and a clean deterministic conclusion tolerate
it, because local packs never read native captured bytes, and an AI-powered finding treats it as a
capture baseline (tolerated only when the raising review ran under it too). The workspace
`content_capture_unavailable` flag in observation status is unchanged and remains workspace-wide.

`content_capture_pending` means encrypted staging is durable while structural ledger ingest is still
pending. It is separate from `operation_pending`, which is generic observation back-pressure and
makes no claim that content was retained. Up to 512 `staging`/`pending` tickets may be outstanding
per workspace; revoked tombstones are excluded from that quota but retained to fence ABA reuse. A
new check/frozen-case acquisition sees an outstanding ticket in the same bundle transaction and
returns retryable `OPERATION_PENDING` with `reason_code: check_admission_capture_pending`,
`retry_after_ms`, and the `check_admission_same_identity` continuation; retrying the same request
is idempotent. When a new CHECK
encounters this barrier, READY performs a bounded listing for the exact routed task and reconciles
each ticket against current local content authority before one freeze retry. This task-local
preflight retires tickets whose authority is absent, inactive, revoked, runtime-disabled,
profile-unselected, or from an old authority generation, including tickets left without a structural
outbox row. When the capture lock is free it then also retires an active ticket at least
`CAPTURE_HANDOFF_RECONCILE_AGE_MS` (30 seconds) old whose structural row is neither in the outbox nor
in the selected-admission buffer (issue #836); a younger ticket, or one whose row is still queued,
retains the retryable barrier. A CHECK never waits for the capture lock. A completed same-request
replay returns without inspecting newer tickets. It does not rewrite captured history or encrypted
objects. The refused check held both dispatch gates; the daemon wakes the observation sweep
as the refusal leaves so pending structural delivery can run before the bounded replay (#838).
The capture lane can stage while a heavy append runs, while its bounded object/manifest writes stay
serialized. This boundary provides local encrypted durability only: there is no plaintext spool or
offline guarantee, and a host kill or service failure before authenticated staging may leave the
honest `content_capture_unavailable` gap. Captured-content staging does not authorize AI-powered
review egress: repository privacy selection and provider-attempt authorization remain independent.
Codex's historical session-stream path is unchanged and excluded from this native ticket lane;
shared replay, generation-fence, and teardown behavior applies across hosts.

Admission-independent recovery (#695) uses private application methods, not a new RPC:
`LocalObservationStore.capture_inventory_recovery_needed(workspace)` reports unknown scope or
an unreconciled reservation. `pending_workspaces()` includes that durable demand even with an
empty outbox. `ObservationCoordinator.recover_capture_inventory(workspace)` returns
`ObservationCaptureRecoveryOutcome` or `None` when recovery is not needed. It routes only existing,
unambiguous lifecycle mappings and invokes the same complete inventory callback under the shared
capture lock. The READY `ObservationOutboxSweeper.capture_recovery` callback runs before per-workspace
drain leases and outside the workflow-control gate. It rotates at most four workspace candidates
per pass with a five-second cooperative budget, and tries at most eight mapping candidates per
workspace before yielding. Started synchronous metadata/publication workers are joined on
cancellation; a timed-out operation cannot publish after its capture lock has been released.
The service callback verifies opened runtime task/session identities and supplies an internal
`proof_guard` to `bootstrap_capture_reservations`; it rechecks the READY service/vault generation
under the local-store publication lock. A false or failed guard leaves accounting unknown.

A stranded native handoff is the same kind of admission-independent maintenance demand (issue
#836). `LocalObservationStore.capture_handoff_candidates(workspace, older_than_ms=30_000)` returns,
oldest first, the task routes whose central reservation or cached task snapshot is at least that
old; it also returns routes with pending retirement confirmation so restart cleanup is retried;
`pending_workspaces()` includes such a workspace even with an empty outbox. After inventory is
known, `recover_capture_inventory(workspace)` reconciles at most eight of those tasks per turn under
the shared capture lock, and returns a tuple when both steps report. READY supplies
`ObservationCoordinator.capture_handoff_reconcile`, which opens each named task through its active
catalog route and session binding rather than a host-session mapping, so a handoff left by an ended
session stays reachable; without it only mapped routes are reconciled. For each task the
coordinator reads `capture_handoff_structural_state(workspace)` (outbox rows and selected inputs
that can still be delivered, and quarantined rows with their reason) before listing tickets, then
tombstones a ticket whose authority fails the CHECK-preflight rules, or which is at least 30 seconds
old and has no deliverable row. The ordering is sound under the capture lock: no handoff can be
staged during the pass, and a delivery deletes its ticket before the drain acknowledges or
quarantines the row. Each visited task's backlog is republished, which also releases a reservation
that outlived its completed or tombstoned ticket. A handoff kept by current authority and a queued
row is retained and still counts toward the unchanged pending-age limit. The coordinator keeps a
bounded per-workspace cursor after the last attempted task route; each turn rotates the deterministic
oldest-first candidate list from that cursor before taking eight routes. An unavailable prefix
therefore cannot starve a later owning route, and the cursor changes scheduling only, never task or
capture authority.

The closed internal recovery outcomes are `capture_inventory_recovered`,
`capture_inventory_mapping_missing`, `capture_inventory_route_unavailable`,
`capture_inventory_unknown`, `capture_inventory_disabled`, `capture_inventory_busy`,
`capture_inventory_timeout`, `capture_handoff_retired`, and `capture_handoff_unavailable`
(an owning task could not be opened or read; the next sweep retries). A turn that retains every
aged handoff reports nothing. They contribute only fixed reason counts to
`ObservationDrainSummary.reasons`, not row delivery/attempt counts, coverage gaps, or raw
exception text. No new RPC or event schema is introduced. `recovery_routes()` owns a separate
read-only connection for each file-backed complete scan and joins its worker on cancellation.
The shared writable catalog connection never crosses to that worker.

Every stranded-handoff retirement is also named locally. `record_capture_handoff_retirement`
records `content_capture_unavailable`, increments `capture_handoff_retired_count`, and keeps the
last 16 entries in the owner-private workspace state as `capture_handoff_retirements`. An entry
holds the opaque `ticket_id`, `stage` (`structural_committed`, `structural_refused`, `sweep`, or
`check_preflight`),
`reason` (`content_not_admitted`, `terminal_refusal`, `structural_row_absent`,
`structural_row_quarantined`, `authority_absent`, `authority_inactive`, `runtime_disabled`,
`authority_generation_changed`, or `profile_unselected`), `ticket_state` (`staging` or `pending`),
`source`, `task_id`, `age_ms`, the closed `quarantine_reason` of a quarantined row or null, and
`retired_at`. It carries no source identity, content, path, or exception text. `finishup observe
status` reports the account as `capture_handoff_retirements` (`retired_count` and `recent`); it is
local-only and outside the frozen control-result schema, like `summary_refusals`. The account is
committed before the ticket is tombstoned or its central reservation is released. Its ticket
identity makes a replay after cancellation, crash, or a later store failure idempotent; if the
account cannot be committed, the ticket and reservation remain active for retry. Accounted
identities whose reservations are still active are pinned within the outstanding-reservation bound,
so repeated retirement failures cannot evict their replay key and inflate the loss count.
The store also keeps up to 512 pending ticket-to-task accounting bindings until destructive
retirement and reservation release are confirmed; this covers legacy tickets that have no central
reservation to pin. A full pending set fails closed and leaves the ticket active for retry. On a
restart or uncertain confirmation, reconciliation compares each binding with the complete active
ticket listing for its task and drops only bindings whose tickets are absent. A task bundle must
report the native-ticket schema as available and return fewer than the 512-row listing cap; an
unavailable schema or capped listing preserves every pending binding and retries later.

`finishup observe status` also reports two more local-only accounts, outside the frozen
control-result schema like `summary_refusals` (tb4n5, ADR-029 amendment of 2026-10-13).
`pending_attempt_endings` is `{"counts": {<reason>: n}, "open": n, "recent": [...]}`: how
pending hook attempts ended without their post, by the closed reason `ttl`, `session_end`,
`generation` (each recorded `pending_attempt_expired`) or `rejected_by_yoetz` (FinishUP's MCP server
answered the call with an error, which a host sends no post for; no gap), and the newest 16
endings as `{"call", "ended_at", "generation", "reason", "tool"}` where `call` is an opaque
16-hex digest of the pairing key and `tool` the structural tool name. `local_retention` is
`{"envelope_ring": null | {"first_seen", "last_seen"}, "dedup_fence": ...}`: the local copies the
bounded ring, state bound and dedup fence shed, which is never content loss and never
`truncated_payload`. `held_rollout_items` is `{"count": n, "oldest_read_at": null | <time>}`: the
Codex rollout tool items still held for their hook post (#910). `delivery_lag` is the outbox
delivery measure, enqueue to the acknowledgement after the service accepted the row:
`{"measured": "enqueue_to_accept", "count", "bucket_upper_bounds_ms", "bucket_counts", "p50_ms_at_most",
"p95_ms_at_most", "mean_ms", "max_ms", "last_ms", "since"}` (only `measured`, `count` and the bounds
before the first sample; a quantile is `null` above the last bound). Each `ObservationOutboxRow`
carries the optional `enqueued_at` it is measured from, outside its row identity. The hook
diagnostic `drain_budget_exhausted` is renamed `drain_pass_delivered_nothing` (one drain pass
delivered no row within its budget) and old rows are read back under the new name (ADR-022
amendment of 2026-10-13). The FinishUP MCP bridge's rejection record (`record_rejected_finishup_call`,
`observation/yoetz-rejected-calls.json`, schema `yoetz.rejected-calls/2`) holds per entry only
`sha256("yoetz/rejected-call/v2", tool basename, session_id, writer_id, request_id)` (an absent
or invalid session or writer commits as `-`) or, for a `publish_work` whose arguments have no
`request_id` key (issue #1084: the bridge mints that id after the host's pre-event),
`sha256("finishup/rejected-call/body/v1", tool basename, session_id, writer_id,
canonical_encode(arguments))` over the agent's own arguments (none when they have no canonical
form; the served-read record keeps the `request_id` form only), a millisecond time, and the
opaque claimant digest of the one pending attempt that consumed it, 256 newest. A hook pre-event
of a FinishUP tool keeps the same commitment on its pending attempt (`_OpenPre.request_commitment`); the Claude Code and
Cursor adapters compute it from the host payload and pass it to the shared ingress as
`_request_commitment`. `consume_rejected_finishup_call` claims an entry installation-wide under the
record's lock and is idempotent for its claimant. On the Cursor host profile only, the bridge also
records each successful FinishUP read it served (`record_served_finishup_read`,
`observation/yoetz-served-reads.json`, schema `yoetz.served-reads/1`, its own lock): the same
commitment and a millisecond time, 256 newest, written before the result returns. The Cursor
adapter passes `_proven_finishup_read` to the shared ingress only for a `postToolUse` of
`MCP:<tool>` whose own `tool_input` claims an entry (`claim_served_finishup_read`: the matching entry
is removed under the record's lock, so one served read proves at most one post-event, and an
entry older than `SERVED_READ_MAX_AGE_MS`, 120 s, proves nothing); the self-observation policy
then reads it as `finishup:<tool>`. The MCP request carries neither Cursor's conversation nor its
tool-call id, so neither can join the commitment; single use and the expiry bound it instead. Nothing else treats `MCP:<tool>` as FinishUP-owned (tb4 n5).

`LocalObservationStore.pending_selection_losses(workspace)` returns at most 64 retained,
fully validated and routed lanes; `selection_loss_workspaces(task_id)` filters the returned
maintenance work to one authenticated task after bounded durable workspace discovery.
`acknowledge_selection_loss(workspace, lane)` follows committed
reporting. `ObservationCoordinator.reconcile_task_selection_losses(runtime)` imports only that
task's historical losses before a new check freezes its inputs. Existing check operations bypass
this reconciliation. The service sweep attempts eight lanes per workspace turn with a rotating
cursor. A terminal route drift or quarantined marker operation uses the supplied same-task
runtime and a distinct deterministic recovery operation identity; transient publication failures
remain fail-closed. Route-valid lane-digest mismatches receive an explicit unreconciled loss
marker; malformed routes or source identities remain local accounting and are not attributed to
a task by the recovery path.
A service-authenticated `evidence_recorded` marker carries `observation_input_loss` in coverage;
`TaskObservationPort.record_selection_loss` records an internal `observation_gap` in task history
without using native admission or advancing its cursor. Its `selection-loss/1.0.0` cursor namespace
is internal bookkeeping, not a native read position. Full original attribution is retained in
the evidence payload and selection route fields. One task-wide operation per lane makes
commit-before-ack recovery idempotent; source/authority generations and original session/writer
remain part of lane identity. Unrouted and overflow-only history remains local. A successful
inventory does not clear loss identity/count history or bypass a real hard capacity limit.
`LocalObservationStore.selection_history_gaps` attaches `observation_input_loss` to a later
input only when that input's call (or the call that spawned it) matches a bounded pairing
commitment of a lost input in the same lane; legacy, overflowed (more than 16 lost calls) or
older-writer-advanced lanes stay route-wide (ADR-029, tb4n1 B3). `record_admission_loss(...,
cause=AdmissionLossCause)` records the closed refusal cause in that private per-lane detail;
`selection_loss_causes(workspace)` and `admission_loss_cause(workspace, envelope)` read it. The
wire loss-range shape is unchanged; hooks surface the cause as the `admission_loss_<cause>`
diagnostic reason.

Outcome semantics and back-pressure vocabulary (ADR-022 decisions 12–13):

- Paired `PostToolUse` materialization consumes `exit_status`, `denied`, boolean `success`, and a
  closed `result_status` spelling table. Rollout `exit_code` preserves the structural wire range
  `-1..255` exactly (including `-1` as a nonzero failure); a present value outside that range or of
  another JSON type is unsupported evidence, never a clean `completed` success, and a `null` value
  (a declined or unfinished command) states no outcome. The Codex hook mapping reads these facts
  where Codex states them, nested in `tool_response` (issue #910): a shell/exec result's
  `exit_code` (object, or JSON text carrying an exec-result key), the `Exit code: N` /
  `Process exited with code N` function-output header, and an MCP result's `isError`; output text
  is never read as an outcome. A rollout `event_msg`/`item_completed` whose item is a
  `CommandExecution`, `McpToolCall` or `FileChange` is a completed tool call (event kind
  `item_completed`) whose `status` and `exit_code` are its outcome. The Claude ordinary
  `claude-code-hooks-ordinary-v2` mapping also treats Claude's documented `PostToolUse` event as
  an explicit host-tool success fact, without fabricating `exit_status: 0`; `PostToolUseFailure`
  and explicit failure, denial, interruption, invalid/unknown status, or conflicting facts retain
  their failure/partial/unknown meaning. A background Bash launch remains partial without
  completion evidence. For mappings without such an event contract, a payload with no outcome fact
  records `UNKNOWN` and its ledger entries carry the `host_outcome_unavailable` known gap. Check
  coverage and receipts fold that gap into one bounded code regardless of how many observed calls
  lack outcome semantics; the local research-evidence policy does not mint one
  `material_limitation_omitted` candidate per such record. Observed work facts (durable per-call
  action/result records), the acquisition limitation (`host_outcome_unavailable` coverage gap),
  actionable findings (explicit `FAILURE`/`PARTIAL`, cooperative `UNKNOWN`), and receipt gaps stay
  distinct surfaces. When the session stream later appends the corrected outcome for the same
  action (`materialize_observation_outcome_correction`), the unknown hook result is superseded for
  readers (`kernel/outcome_corrections.superseded_unknown_results`): check totals count that call
  once with the recorded outcome, and the frozen case drops that record's
  `host_outcome_unavailable` gap. Both ledger rows stay immutable (#1001).
- `operation_pending` is the retryable ingest-rejection reason for designed observation
  back-pressure (check-acquisition/frozen-case barriers and adjacent transient bundle/frontier
  contention). It keeps the outbox row pending and annotated, but is never a current observation
  gap, never a hook failure diagnostic, and never projects `service_unavailable` into status,
  advice, coverage, or receipt inputs.

Canonical normalization precedes materialization. Equivalent hook/stream host calls share logical
identity, roles, operation digest, and stable ledger IDs. That canonical logical identity remains
the ledger-dedup key. Captured-content manifests use a narrower phase identity derived from that
canonical host call plus normalized phase. Equivalent hook/stream copies of one completed phase
therefore share recovery, while Pre/Post/unpaired siblings remain isolated. Manifests are recovered
before materialization, including on a content-less durable-outbox retry. For pre-amendment rows,
the matching source group may supply usable content; every legacy source group is also kept as a
separate lookup-only role candidate so an equivalent post-upgrade stream copy can find a hook
commit. Recovery authenticates each encrypted object's kind, media type, canonical envelope, and
inner plaintext digest. A complete readable manifest set may strengthen a new materialization; an
incomplete, legacy-unbound, contradictory, orphaned, or unreadable set is used only to reconstruct
candidate role tuples for completed-operation lookup and never grants captured coverage. Once a
phase has durable manifests, later equivalent-source chunks cannot expand its stable role set. The
content-independent core role tuple is also a replay candidate: if a core-only operation committed
before content arrived, the later copy reuses it and records `content_capture_unavailable` rather
than reminting its event IDs or retroactively upgrading its coverage. The role-scoped operation
digest can therefore find either committed ordering without changing event IDs. Missing, incomplete,
contradictory, or unreadable objects add `content_capture_unavailable` rather than being inferred.
The durable repository claim is separately domain-scoped by the materialization mapping version and
exact draft-role tuple, so phases of one host call with different materializations (for example
pre-action versus paired action/result) cannot collide, while hook/stream copies of the same phase
still share a claim and merge its two-bit source mask. The claim stores the source-independent
materialization version, never the hook/stream cursor version (issue #309). Before staging under
`obs-ledger/1.5.0`, replay first resolves the task-scoped current identity task-wide, so a
reattached FinishUP session finds the operation its predecessor session committed (issue #560), and
then checks the current and legacy observation writers for committed session-bound `1.4.0`, `1.3.0`,
and `1.2.0` operations; a legacy hit repairs its claim with the original mapping version. A
task-wide hit whose stored request digest differs is a conflicting reuse of the operation identity
and fails closed as non-retryable `IDEMPOTENCY_CONFLICT`. Because a replayed `1.2.0` operation may
be a pre-upgrade hook operation whose result is `UNKNOWN`, it still enters the correction path: the
committed result is consulted through the replayed operation's accepted event ids (its `1.2.0`
record identities cannot be re-derived), and a still-needed correction binds to that exact committed
action. A later explicit session-stream outcome enriches an earlier hook `UNKNOWN` through an
append-only `result_correction` linked to the same canonical action; it never rewrites, downgrades,
or silently overwrites an explicit result. Exact correction retries replay; a contradictory explicit
outcome appends under its outcome/exit-bound identity with a `dedup_conflict` gap. A call-keyed
delivery (event ids derived from the host call: a paired pre/post, a Codex stream completion, a
post-only post that names its call) none of whose reconstructable role sets is committed, but whose
every event id the task ledger already holds, is a duplicate, never a content refusal: nothing is
appended, the correction still applies, and an append refused as `EVENT_INVALID` is re-read the same
way before it can quarantine (issue #1027, tb4n3 N3-7). A Codex stream completion is bound to its hook
call's generation before its captured-content manifests are looked up, so a content-bearing hook post
and its contentless stream copy resolve the same committed operation across a `compact`, `resume` or
`clear` generation bump. Event ids derived from a source identity alone (unpaired evidence) can be
reused by another call, so a collision there still fails closed as `ledger_rejected` (#560).
For call-keyed partial overlaps, the coordinator validates the committed core action/result and
existing evidence against the current projection, then appends only missing drafts (#1078,
PR #1080). Delivery times, rendering and evidence-reference sets may differ; command identity,
action identity and existing evidence content must agree. Stream outcome differences retain the
append-only correction and its conflict disclosure. A smaller committed role set cannot swallow
new captured input, output or digest-only image evidence. New evidence's existing `reference`
field names the original action event when validated causal parents establish that link; only
observation-captured provenance can supply this link to review selection. Its run frontier stays
the original result frontier, and F1 authentication is still required. An already-recorded captured
object is reused rather than assigned a second evidence identity, preserving unique authenticated
object association. Distinct image source identities retain distinct digest-only evidence.
Enrichment operation/claim roles include their appended event IDs, so different enrichments do not
collide. One immediate reconciliation handles a racing partial append; further agreeing races stay
retryable rather than quarantined. Real conflicts still reject atomically. The correction is part of ingest acceptance: an unavailable, lagging, rebuilding, missing-result, or redacted-result
candidate-findings projection returns retryable `service_unavailable` and leaves the outbox row
pending until the projection can prove and complete the correction. Duplicates retry incomplete
content/store/ledger/verification/advice work idempotently. Stream cursor advancement occurs only
after outbox insertion. Session end is generation-scoped; a newer start clears only the old stopped
fence. Drain is bounded round-robin across workspace sessions under a nonblocking per-workspace
lease; within one pass a `mapping_missing` rejection retires that session's remaining rows (stamped
with the shared cause), and an ended unmapped session is terminally quarantined because no future
mapping can deliver it, but only after atomically acquiring its lifecycle lock so an attach already
in flight wins. The service sweeper yields with its partial summary once a pass has run for its
20-second budget, under the daemon's 30-second sweep deadline, so rows it resolved license the
immediate re-sweep instead of being discarded as a deadline timeout. A row's attempt, coverage gap,
lane reason and acknowledgement or quarantine commit in one local transaction after the service
answered, never before it. A pass that meets a contended store stops with its partial summary and
the closed `observation_store_busy` reason instead of failing; an answered row whose settlement lost
that race stays pending and replays as a duplicate. A workspace whose admission maintenance is
contended sits that pass out (fail-closed) while other workspaces drain (issue #689). The installation maintenance
gate covers one coordinator ingest at a time rather than the whole pass, so a backlog cannot hold
ordinary workflow control behind local outbox bookkeeping; the workspace lease and the routed task
fence still serialize each row against recovery and bundle rotation. Legacy hook-spool normalization
uses one generation-owned worker, advances a durable byte cursor in bounded batches, and retains its
claim future across cancellation, so a later pass cannot overlap the same rename-and-replay
operation; generation close stops between batches. The route inspection and fence verification
callbacks keep their synchronous SQLite snapshots off the control event loop. The manual `finishup
observe drain` repeats full FIFO passes while the previous pass resolved at least one row, bounded
by the backlog size at entry, and reports `passes`, `pending_after`, and a closed `terminal`:
`drained` (nothing pending), `retry_pending` (a pass resolved nothing; `reasons` names the retryable
heads), `service_unavailable` (no connection; exit 20), or `pass_limit` (rows kept resolving until
the bound, so a producer is still adding them). `finishup observe status` reports
`oldest_pending_receipt`, the receipt time of the oldest pending row, beside `last_successful_drain`
(issue #564). A consented `SessionStart` auto-attaches by sending the service a `start` request in
`create_or_attach` mode whose selector is the paired identity the start contract requires: the
canonical workspace locator the hook already bound consent to as `workspace_ref`, and the
host-session identity as `external_ref`; the service persists only HMAC commitments of both, and a
hook that reached consent through the legacy session→workspace map without a canonical locator
never sends an unpaired request (issue #459). The request validates through the public
`StartRequest` contract before dispatch. Before automatic new-pair admission, the shared Claude
Code/Codex/Cursor hook path checks the private local store for a held mapping from a durably recorded
same-host `SessionEnd`. A unique eligible mapping is the only automatic recovery selector: the hook
holds the workspace and predecessor lifecycle locks, revalidates ownership and state, and sends one
`mode=attach` request carrying that selector together with the new host pair. Every eligible mapping
must name one task; within it, the newest mapping-file write wins and the host session ID breaks
timestamp ties. The trusted control handshake carries the canonical workspace for repository privacy.
The catalog requires the selected root task to remain active and non-quarantined, its canonical
workspace and trusted repository-privacy binding to match, and no start for that selected route to
be pending.
Other tasks in the workspace do not make a held selector ambiguous and are neither attached nor
changed (#814). The new pair must not already select a different task. Delegated child routes
remain authenticated-handle/target-selector paths and are never discovered by generic session
recovery. This permits independent tasks to coexist; it does not grant task interaction, delegation,
lineage, or shared project authority.
Both calls share one five-second deadline. The response must retain the candidate task ID. Recovery first takes a nonblocking
workspace reservation and then holds ordered locks for every eligible ended same-host session
through full candidate revalidation, the service RPC, authorized rewrites, and pruning; no
observation-store lock spans the RPC. Revalidation includes unmapped sessions, cross-workspace
ownership, mapping identities, and mapping recency. A busy workspace reservation returns
`auto_attach_recovery_busy` without a service request; a busy candidate lock or changed snapshot
returns the same closed `auto_attach_recovery_busy` boundary rather than creating work while the
selector is unstable. If eligible mappings name more than one task, admission returns the closed
`auto_attach_binding_ambiguous` reason with only a bounded candidate count and does not guess. A
successful recovery records the new mapping, rewrites every ended same-host predecessor mapping for
that task to the rotated session and writer, and drains pending rows without publishing an
intermediate conflict. With no usable persisted selector, automatic `create_or_attach` admits the
new pair as independent work, including beside a dormant task. `workspace_task_exists` identifies
only explicit `mode=create` colliding with an identical pair; workspace membership never supplies a
selector. Predecessor rows still pending
at rotation follow the `session_superseded` binding on ingest (the current task session and the
observation writer derived for it) so they are acknowledged on the successor route rather than
quarantined. When no eligible local selector exists, the ordinary `create_or_attach` path admits
new work; when recovery attach fails, the ordinary typed failure path remains. Every failed attempt records a
closed hook-diagnostic
reason instead of a silent absent mapping: `auto_attach_workspace_unbound`,
`auto_attach_request_invalid`, `auto_attach_binding_ambiguous` (candidate count only),
`auto_attach_conflict` (session, idempotency, or request-identity conflict), `auto_attach_refused`,
`auto_attach_result_invalid`, `auto_attach_mapping_write_failed`,
`privacy_authority_required`, or the shared `service_unavailable`, `service_incompatible`, `vault_locked`, `timeout`,
`storage_unsafe`, and `storage_corrupt` tokens. Turn-boundary hooks retry auto-attach under a
bounded budget and record the same typed cause next to the `auto_attach_retry_failed` path marker
when no mapping results. Busy lifecycle mutations are durable: observation-local schema `/11` adds a
bounded `pending_lifecycles` queue and source/session/generation-scoped paired-orphan identities,
and hook or READY drains reconcile them under the same workspace and session reservations before
routing rows. Historical false post-only diagnostics are retired only when retained envelope history
is complete; their gap-history rows remain. Busy mapping writes use an atomic per-session handoff.
Applying a handoff claims a separate file, retains concurrently queued updates, and replays an
interrupted claim on the next attempt. A deferred clear superseded by a later generation cannot
remove that generation's mapping. The `/11` extension requires a quiesced upgrade: stop the older
FinishUP service and all host hooks, install the new runtime, then restart the service and every host
integration before writing the new state. Mixed old and new writers are unsupported because a `/10`
writer ignores the new fields and can erase pairing provenance when it saves. The resume/compact
status read for a mapped session connects through the same consented workspace locator as the
auto-attach `start` (`finishup hooks session-start` derives it from `--workspace` or, absent that, the
hook's own working directory), so the daemon's repository fence admits a live mapping (issue #578).
A `SESSION_NOT_FOUND` answer (`session_superseded`, whose advisory now names the superseding task,
session, and writer ids) or a `SESSION_CONFLICT` without a fence reason (a replaced writer route)
classifies as `mapping_stale`, not service unavailability: the hook preserves the mapping, tells the
agent to continue with the named ids or to call `start mode=attach` with the mapped session id, and
accepts only a successful `start` result as authority for replacement ids. A `SESSION_CONFLICT`
carrying `repository_identity_required` or `repository_identity_mismatch` is a live mapping the
daemon could not bind to a repository: it records `status_workspace_unbound` /
`status_workspace_mismatch`, keeps the mapping, and its advisory says not to re-attach.
`cli/hooks.resolve_session_workspace` selects the probe's locator in a fixed order — explicit
project path (not the bare `.`), host payload `cwd`, hook cwd — and returns a closed
`SessionWorkspace.source`; beside a fence refusal the hook records the companion row
`locator_source_explicit` / `locator_source_host_payload` / `locator_source_cwd` / `locator_absent`
/ `locator_unresolvable` (issue #659). An explicit path that fails canonicalization never falls
through, and the daemon's fence still decides admission, so a derived locator can produce a typed
mismatch but never access to another repository. The active-mapping context names the task,
frontier, `session_id`, and `writer_id`, and says to continue the task with `start mode=attach` by
that session id rather than a new ref pair (issue #580). The scoped `start` post-hook binder admits
three host shapes — an object carrying `structuredContent` (Codex), a single-text-block content list
whose text is the strict-JSON result, and a bare JSON string of the structured result (the shape
Claude Code 2.1.251 passes as `tool_response`, captured live 2026-09-04) — and records
`start_bind_unparsed`, `start_bind_invalid_ids`, or `start_bind_write_failed` when a scoped
successful start produced no mapping (issue #581). Only an explicit boolean `ok: false` is treated
as a refused start and records nothing; a missing or non-boolean `ok` records `start_bind_unparsed`.
`OPERATION_PENDING`, `BUNDLE_BUSY`, and `FRONTIER_CONFLICT` are transient status reads; vault and
repository-privacy failures retain their distinct recovery advisories. `STORAGE_UNSAFE` and
`STORAGE_CORRUPT` keep their own advisories because they prescribe opposite next steps — a fault
that may be retried once versus invalid data that must not be retried and is escalated to the
operator — and the hook records the same lowercase token (`storage_unsafe` / `storage_corrupt`) as a
payload-free diagnostic so the advisory, `hook_diagnostics`, and `observe status` share one
vocabulary (issue #338). The closed public-error table is exhaustive so a new code cannot silently
inherit an unrelated advisory (issue #308). `observe status` retains the current and rotated
hook-diagnostic history, but pairs every all-time reason count with `first_seen`, `last_seen`, and a
count in the closed one-hour `window_seconds`; timings likewise date the all-time maximum and report
a separate recent maximum. Unreadable or future timestamps remain retained but are never classified
as recent, so a fixed historical failure cannot masquerade as live degradation (issue #310).
Workspace-global rejections (`vault_locked`, disabled, paused) end the pass. A host's automatic
reviewer holding a scoped AI-powered `check` before FinishUP receives it is recorded on the
`PermissionDenied` event as `host_auto_review_denied` or `host_permission_rule_denied` (issue #467);
it is host tool-call authorization, so no AI-powered review status is ever inferred from it. The
same event records what the hook then said about the hold (issue #857): `host_denial_retry_offered`
(grant confirmed first-hand, the session's one `retry` emitted), `host_denial_retry_exhausted`
(grant confirmed but the retry was already spent, the owner's own rule held the call, or the host
produced no verdict), `host_denial_retry_unrecorded` (the retry ledger was full, unsafe, damaged, contended or unwritable, so no
retry was emitted), or `host_denial_grant_unconfirmed` (the grant could not be read inside the hook
deadline). Every
host ingress (Codex, Claude Code, Cursor) that ingests nothing because of workspace binding records
one payload-free diagnostic naming the dropped layer: `workspace_unresolvable` when an explicit
`--workspace` locator cannot be canonicalized (an empty value from an unset `CLAUDE_PROJECT_DIR`, a
missing, symlinked, or unsafe path), `workspace_unconsented` when the canonical locator carries no
active consent, and `paused` when consent is paused. The fail-open `{}` stdout is unchanged; the
diagnostic is what lets `observe status` distinguish a hook that fired and was dropped from one that
never fired (issues #420, #435). `finishup observe` verbs report the same pre-store conditions as typed
public outcomes rather than `internal_error`: `workspace_unresolvable` exits `INVALID_REQUEST` (2)
with its remediation, an unsafe local state path or unsafe lock-file shape exits `STORAGE_UNSAFE`
(20), and a bounded open, permission, read-only, missing-parent, or lock-acquisition failure exits
`SERVICE_UNAVAILABLE` (20) with reason `storage_unavailable` and a retry remediation. Existing
invalid stored data remains `STORAGE_CORRUPT` (40), while non-filesystem defects still reach the
`internal_error` boundary. The filesystem mapping renders only fixed reason/remediation text and
never includes the raw exception or absolute state path. `--json` callers receive one `error` object
carrying `code`, `reason`, `retryable`, `operation`, and the bounded message (issue #428). A
`service_unavailable` rejection retires that session's lane for the pass while other sessions remain
eligible; no later row may step over a failed lane head. Local observation-store acquisition is
capped at two seconds for both the process-local reentrant lock and the cross-process flock, and a
caller may shorten that cap with one monotonic deadline for every acquisition in its scope: a hook
pass bounds all of its lock waits by its host window (2 s after entry for a 3-second SessionEnd,
3.5 s for a 5-second Claude Code or Cursor tool event, 7 s for a 10-second Codex observe hook or
Claude Code/Cursor SessionStart and Stop), and a sweep bounds its pre-delivery hops by its pass
budget (issue #689). Reads never take the lock: every workspace document is replaced atomically, so
a read observes one committed version, never another writer's open transaction; a read-mostly
operation that reaches a write (a legacy repair) reruns under the lock. The depth-one flock holder
stamps its closed role (`hook`, `service`, `sweep`, `coordinator`, `spool_replay`, `cli`, `local`),
its store phase (a code identifier) and its monotonic start into the lock file and clears it on
release; a timed-out waiter raises `ObservationStoreLockTimeout` (a `TimeoutError` whose text stays
`observation_store_lock_timeout`) carrying the scope (`thread` or `process`), the holder's role,
phase and hold time, and whether an in-process holder was itself still queueing for the flock.
The exception is defined in the lightweight `finishup.ports.observation_errors` boundary and
re-exported by `finishup.ports.observation` so native hooks do not load service policy or wire-model
dependencies. Hooks record those facts, and holds of one second or more, as payload-free `store_lock` rows
(`store_lock_timeout`, `store_lock_long_hold`) listed under `store_lock_events` in `observe status`
hook diagnostics; the service records them as `observation.store_lock.<role>` diagnostics.
Hook diagnostic readers discard malformed lock rows, including non-string role and scope fields.
An interrupted pre-flock preparation releases its process-local lock before propagating the
interruption, so subsequent writers can proceed. Hook timing rows attribute queueing as
`store_lock_wait` and the pass's own critical sections as
`store_lock_hold`, cover the previously unwindowed resolve/deliver regions, and name any remaining
wall-time difference as `unattributed`; nested store sub-stages are reported separately from the
end-to-end partition (issues #310 and #311), as is `fingerprint`, the before/after workspace
fingerprint inside `resolve` (PR #1080). Timing rows stay reserved for over-budget passes,
session boundaries and legacy-spool hard-cap breaches, so routine passes never evict the
failure-reason window. The cost of every observation-ingress hook pass lives in a separate
fixed-size aggregate (issue #915): each host ingress entry (`hooks observe` and `hooks spool` for Codex,
`hooks claude-observe`, `hooks cursor-observe`) folds exactly one sample per process into the
owner-only `observation/hook-pass-timing.json`, keyed by host (`codex`, `claude`, `cursor`), raw
host event name, and path (`observe`, `sync_fallback_spool`, `structural`, `ordinary`,
`invalid_profile`), with an outcome tally (`ingested`, `followup_deferred`, `not_ingested`,
`failed`). Hook commands outside those ingress entries (Codex `hooks session-start`,
`hooks user-prompt-submit` and the `start`-scoped `hooks post-tool-use`; `hooks startup-gate` and
`hooks startup-context`) contribute no sample, so the aggregate is not a complete per-host hook
cost profile. A sample is in-process time from the console entry to the end of the pass, after the
host output was written; interpreter start and process exit are excluded. Each entry keeps the exact
count, sum, mean and maximum, a fixed-bucket histogram whose edges include 150 ms, 250 ms, 500 ms and
the 3, 5 and 10 s host timeouts, and the same histogram for the current and previous clock hour
(`recent`, dated by `since`). `p50_ms_at_most` and `p95_ms_at_most` are the bucket bound that the
nearest-rank percentile falls at or below, never an interpolation. The document holds at most 48
entries (evictions are counted) and 64 KiB. Writers serialize on an exclusive lock, stage the
next document beside the aggregate and rename it into place, and do not fsync; the aggregate path
therefore only ever names a complete document, and a write that fails part-way leaves the previous
one. A document that fails validation, including a timestamp past year 9999, reads as `unreadable`
and restarts with a new `since`. Readers take no lock and create nothing: a status read on a state
directory without the aggregate reports `absent` and leaves no directory, lock or file behind, and
a read racing an update sees the last complete document. Every writer acquisition of the lock is
bounded to 100 ms, so a stalled holder cannot keep a hook past its host timeout: a writer that
cannot take it drops its sample and appends one byte to a lock-free drop counter, reported as
`dropped_sample_count` (a lower bound for the period `since` names). Nested calls and the service's legacy-spool replay run the observe pass without a
host entry and contribute no sample. `observe status --json` reports the aggregate as
`hook_diagnostics.pass_timings`; the text form prints it on a `hook_pass_timing` line. The legacy
spool judges its 500 ms hard cap and feeds the aggregate from one measurement taken after the
host's stdout write. A hook pass whose capture batch cannot take the lock
within its budget still exits 0 with its host's fail-open output, and reports
`store_lock_timeout` instead of the generic `observe` or a false `workspace_unconsented`; that
input is not retained. Serialization splices a cached canonical fragment for each immutable
envelope, outbox row and quarantine entry, and a re-read after another writer's commit neither
re-validates nor re-decodes an envelope whose equal JSON this process already validated, so a
critical section costs what changed rather than the whole document. The bytes written are identical
to inline encoding, and a re-read accepts and rejects exactly the documents whole-document
validation would (a document that fails still reads as an empty, unreadable state). A
conflicting logical-identity claim rejects and quarantines only its own envelope as
`dedup_conflict`; it does not establish bundle corruption or arm the session latch (issue #309).
Coordinator and sweeper calls use separate bounded executors, so cancellation cannot strand an
exit-blocking flock wait or exhaust the shared default executor. The sweeper tracks every worker hop
it submitted; a pass that finds a hop from a cancelled pass still running waits up to five seconds
for it and otherwise yields an empty summary with `observation_store_busy`, so a stranded worker is
never joined by new store work beside it (issue #689). Join observers consume worker exceptions
even after a join timeout or cancellation, keeping raw exceptions out of the event loop's default
error handler; pending rows retain their replay semantics. `observation_storage_corrupt` is
terminal for its Codex session in the current READY generation: the coordinator remembers that
session only after a bundle-level `STORAGE_CORRUPT`, later ingests are rejected without reopening
the bundle, and the sweeper atomically moves that session's pending backlog to quarantine while
healthy lanes continue. A new READY generation clears the in-memory suppression and permits one
recovery probe. A successful probe removes that session from the local corruption set and resolves
the workspace corruption gap only when no affected session remains. Quarantined detail is bounded by
count, by the state byte budget, and by a 14-day age measured from a store-authored quarantined-at
time behind the trusted-clock epoch fence; an operator can drop it explicitly with `finishup observe
reclaim`. Every drop — cap, age, or reclaim — retains aggregate commitment, count (evictions and
reclaims counted separately), first/last receipt times, and `quarantine_detail_evicted`. The
`truncated_payload` gap is live rather than permanent: a later save resolves its active flag only
when that save evicts nothing and leaves one-eighth of the state budget free. Merely landing under
the cap cannot clear the same loss it just recorded; the durable gap history remains after recovery,
and renewed shedding reactivates it (issue #310).

An unexpected exception in a hook pass, or in the legacy synchronous spool writer, is recorded as
`observe_<exception class>` in `hook_diagnostics.reasons`, using the service's reviewed closed
exception-class vocabulary (`observe_exception_value_error`, `observe_exception_os_error`, ...).
An unlisted class, including an unreviewed subclass of a listed one, collapses to
`observe_exception_unavailable`; no class name, message, path or command is kept. The bare
`observe` reason is still admitted for older rows. The drain preflight is split by stage:
`drain_connect_timeout` (the service connect ran past its preflight bound),
`drain_connect_failed` (the connect raised), and `native_content_stage_failed` (the encrypted
native-content handoff raised; the rows stay pending and the content keeps
`content_capture_unavailable`). `drain_preflight_failed` now names only a failed local outbox read
before the connect, and is still admitted for older rows (tb4n2 N-3, issue #1019).

Public ingest failures use their `retryable` contract and the stage that refused the request.
A non-retryable `SESSION_CONFLICT` while acquiring the task runtime becomes `mapping_missing`:
the envelope stays pending so a later drain can recover its lifecycle mapping, subject to the
same route ownership checks. A non-retryable conflict after runtime acquisition, or a
`SESSION_NOT_FOUND` without a followable binding, becomes `ledger_rejected`. Other non-retryable
failures outside the narrower `dedup_conflict` and `observation_storage_corrupt` classes take
that same terminal path: drain and sweep quarantine the row, record the reason once, and continue
its lane (issue #554). A retryable public failure outside the designed back-pressure set and
`VAULT_LOCKED`, including a retryable session-route conflict, is `service_unavailable` and stays
pending. `SESSION_NOT_FOUND` with
`reason_code: session_superseded` is not that class: ingest follows the current binding carried in
`safe_details` (same task, successor session, observation writer derived for it), persists the
updated lifecycle mapping on each hop only while holding the lifecycle lock and the stored
mapping still equals the predecessor, and delivers the row. A busy lock, changed or cleared
mapping, or persistence failure skips this cache update without blocking successor delivery. A superseded payload that cannot be
followed (missing or mismatched task/session/writer ids, a hop cycle, or a rotation after the
route already opened) quarantines that one row as `session_superseded`. It is never
`ledger_rejected` and never `mapping_missing`: `mapping_missing` would retire an ended host
session as unmapped and would disappear from current gaps while the mapping file remains.
A deterministic write rejection inside the SQLite observation store (a CHECK or STRICT type failure, which repeats identically on every retry of the
same envelope) is raised as non-retryable `invalid_request` and takes the `ledger_rejected` path, instead of
escaping as a bare driver exception that the catch-all projected as retryable
`service_unavailable` while the service was ready (issue #576). Retryable failures keep their current reason and
scope. A row that reaches 128 consecutive rejections with the same retryable reason is quarantined
with that reason, so an accidental future catch-all classification cannot create an immortal FIFO
head. Designed `operation_pending` back-pressure and workspace-global pause/vault/disabled gates
are not subject to this ceiling and retain their existing recovery semantics. The terminal reason
remains in `quarantine_causes`, the aggregate `delivery_causes`, and gaps. The
`pending_delivery_causes` field names only pending rows, while `delivery_causes` combines pending
and quarantined delivery failures so terminal causes remain visible after the row leaves the
outbox. Hook-driven drains also write the bounded hook diagnostic, while manual and supervisor
drains are visible through status rather than being mislabeled as hook activity (issue #540).

Observation selection follows ADR-029 and retains ADR-022's individual outcome rules. The shared
`ObservationClassification` derives `routine_candidate`, `proven_routine_success`, protection and
closed reason tokens from supported host structure and conservative single-command parsing.
Caller action labels cannot select `routine_read`. Unknown outcomes, nonzero read results,
denials, cancellation, ambiguous shell syntax, mutation flags and declared verification remain
individual observations. An unknown result is never treated as a successful read.

Focused is the default detail mode. `AdmissionBuffer` retains minimum pre identities and proven
routine successes before optional content extraction and outbox admission. At most 16 completed
calls or 32 inputs contribute to one `RoutineReadSummary`. Summary members retain exact native
identity, source cursor, phase and observation time; the summary binds their digest, original
route, authority generation, selection fence, and explicit structural-only content scope. It
cannot cross source, session, delegate, generation, authority or material-state boundaries.
Summary delivery creates one metadata-only evidence record with `routine_read_detail_omitted`
coverage, not a per-call content or verification claim. A changed task route is rejected before
the observation cursor advances.

There is one definition of a proven routine success. `classify_observation` resolves it from the
host payload, its bounded nested result carriers, and the native post-hook fallback, and the
ingress records that decision on the envelope. A caller holding an envelope rather than a payload
re-derives the same state with `envelope_outcome_state` over the fields the envelope retains, with
the recorded `hook_name` standing in for the host's `hook_event_name` echo; a stream envelope
records no `hook_name` and still requires an explicit outcome fact. A second, stricter rule over
the lossy structural copy accepted only a top-level `exit_status`/`success`/`result_status` fact,
so it refused every Codex-shaped post the planner had already buffered as a success (issue #753).

Refusing to summarize one buffered lane is an accounting loss for that lane, never a stop. The
flush admits that lane's members individually with the durable `routine_summary_invalid` coverage
gap — distinct from `routine_read_summary_invalid`, which describes a delivered summary envelope
that materialization refused — commits the remaining lanes, and drains the buffer. The workspace
retains one bounded, deduplicated refusal account per refused lane (source, session commitment,
source generation, the lane head's native identity and cursor, input count, and the protocol reason
code). `observe status` reports that account beside the `routine_summary_invalid` coverage gap — it
is a local cause record, separate from the selection-accounting projection whose shape the local
control-result schema freezes — so the cause is named once instead of an anonymous sweep exception
repeating every minute. A hook whose own pre-flush still fails structurally records the bounded
`admission_flush_invalid` reason, and a hook that observed a refusal records
`routine_summary_invalid`; neither degrades to the bare `observe` token.

A `SessionEnd` hook whose local session end cannot persist stays fail-open for the host. It
prints `hook_observe_degraded: session_end_unrecorded` and records the bounded
`session_end_unrecorded` reason, because the session and any temporary selection override stay
active until a later end or expiry (#843). The end is saved with the hook's capture batch. If
that batch fails to commit, the hook reports the reason beside the generic `observe` reason. A
fault after the batch committed does not report it. Before this reason, a failed end was either
discarded or reported only as `observe`.

A host body refused at stdin ingress for its size is accounted the same way, per host:
`codex_payload_too_large`, `claude_payload_too_large`, and `cursor_payload_too_large` are the
bounded hook reasons, recorded against the hook event name the host supplied on the command line.
Each host notes the no-row `payload_too_large` coverage gap on the consented workspace when the
body exceeds `MAX_HOOK_SKIM_BYTES` or fails validation inside it; such a body is never parsed, so
the hook name is its only identity. When a host does validate a complete body inside the skim cap
and it still exceeds the trusted cap once its image bytes are dropped, the reason is
`codex_payload_content_omitted`, `claude_payload_content_omitted`, or
`cursor_payload_content_omitted`, and the structural row carries `payload_content_omitted` instead
of `payload_too_large`; a FinishUP-owned MCP tool records neither (tb4n1 B5). Before
these, an oversized Cursor write recorded the generic `cursor_payload_invalid`, an oversized Codex
event degraded to the bare `observe` token, and an oversized Claude Code event recorded nothing at
all (issue #667).

`ObservationSelection` separates Focused/Detailed from the queue-count capacity (the
512/2,048/8,192 profiles or a custom count; see below).
`ObservationSelectionSettings` resolves a live session override, then an explicit workspace
selection, then the default. Each profile also has finite queue/state byte bounds and protected
reserves. `PressureSnapshot` drives future optional-content reduction and temporary Detailed to
Focused behavior from count, bytes, age, pending attempts and capture backlog. Recovery requires
low pressure for the policy dwell and a still-valid owner selection. Status reads do not start
recovery or write notices. Background maintenance flushes due accounts and advances recovery.
The optional `ObservationStatus.selection_runtime` local-control projection carries selected and
effective values, scope/expiry, finite budgets and separate observed, admitted, summarized,
delivered and intentionally omitted counters. The CLI and terminal interface expose this
workspace-bound projection. Ordinary cooperative MCP `status` remains task-ledger scoped and
does not expose or mutate workspace observation selection; use the local observation controls.

Local control schema `2.6.0` adds this bounded observation projection. The frozen `2.5.0`
schemas remain available for local validation and historical fixtures. A client and service with
different schema manifests are rejected during the authenticated handshake, so both peers must
run the `2.6.0` manifest to exchange the new projection; the service does not silently
down-convert it to `2.5.0`. Selection state upgrades preserve pending delivery and default
historical counters to zero, so the new accounting describes locally ingested inputs since the
selection upgrade and never estimates older traffic.

Configurable capacity follows the ADR-029 #828 amendment. `CapacityProfile` (512/2,048/8,192) is
unchanged; `ObservationCapacity` is the owner-selected finite queue count, either one of those
profiles or a custom count from 64 to 8,192 (`MIN_CUSTOM_QUEUE_COUNT`,
`LARGEST_SUPPORTED_QUEUE_COUNT`), with the closed label `standard`, `larger`, `largest` or
`custom`. `ObservationSelection.capacity` and `ObservationSelectionSettings.aggregate_capacity()`
carry it; the settings document keeps the capacity as an integer queue count, and an
out-of-range integer is a malformed setting that falls back to the safe default. The shared
workspace aggregate is the largest of the active workspace setting's count (or the 512 default
when none is active) and every active session selection's count. A session selection can raise
that aggregate but never lower it: a session-scoped custom count below 512 lowers only that
session's own admission, never a sibling's. `BudgetLimits.for_capacity` derives every limit from
the count: queue bytes are 1 KiB per row, state bytes are `max(1 MiB, 2 × queue bytes)`, protected
reserve rows and bytes are a quarter of the count and queue bytes with their existing floors
(64 rows / 128 KiB), each capped at half the queue, session fair share is a quarter of the count
and queue bytes, and pending attempts (256) and capture (512 tickets / 128 MiB) are fixed. For
the three named profiles `for_capacity` delegates to `BudgetLimits.for_profile`, which keeps
their unchanged limits. `STATE_DOCUMENT_CEILING_BYTES` (16 MiB) is the single definition of the
local state-document safety ceiling that the store enforces.

`CapacityRequest` is the parsed owner request (`kind` `profile`, `custom` or `no_cap`), produced
by `parse_capacity_request` from the `--capacity` word or a decimal count plus the optional
`--queue-count`. A no-cap request is valid input whose only answer is the non-retryable
`invalid_request` reason `capacity_no_cap_unsupported`: the structural queue has no uncapped mode
in this storage revision because of the state-document ceiling (`no_cap.reason:
state_document_ceiling`), and the outcome names the largest supported finite capacity. Preview and
apply both refuse it and change nothing. The reason maps to the admitted continuation
`capacity_request_correction` (ADR-030 registry), whose directive tells the agent to have the
owner choose a supported finite capacity, preview it, and apply only that exact accepted
preview; the CLI failure body carries `error.capacity` beside `error.recovery`. The selection
preview payload is
`yoetz.observation-selection-preview/2`; it carries the parsed `capacity_request`, the current
effective budget, and the closed `yoetz.capacity-change-disclosure/1` record (scope, change token,
current and requested limits, closed consequence tokens, limits that still apply, unchanged
authority, lower/revoke/pause/resume commands, `validation_status`). An increase carries the
consequence token `workspace_aggregate_raised` because the shared workspace queue follows the
largest active selection. Every command in the disclosure (`lower_command`, `revoke_command`,
`pause_command`, `resume_command`) and every `next_command` uses the literal `<workspace>` and
`<session-id>` placeholders, never the typed path or session id. Human CLI output and the terminal
interface render that record with one shared renderer and never interpolate user-controlled text.
The preview digest binds the requested count and change token, not live pressure. The CLI no-cap
failure is a standard ADR-030 failure: `error.recovery` carries the continuation and directive,
and `error.capacity` carries the facts as `{no_cap, alternative_command}`.

`ObservationSelectionRuntimeStatus` adds `selected_capacity_label`, `effective_capacity_label` and
the `yoetz.observation-effective-budget/1` record: scope, selected and effective counts and
labels, `effective_reason` (`selected` or `workspace_aggregate`), every finite limit including
`state_document_ceiling_bytes`, the limiting dimension, utilization in basis points, and the
closed `no_cap` availability object. `effective_budget.limits.state_bytes` is the ladder value
for the effective count. While a lowered selection drains, the store never enforces less than the
existing state document's size. While accepted rows still exceed the lowered selection (row count
above its queue count, or admission bytes above its queue bytes), a write that does not fit that
occupancy bound may use the finite over-target bound (ADR-029, #843 amendment): the selected state
bytes, plus the persisted bytes of accepted pending and buffered rows above the selected queue
bytes, plus a fixed 128 KiB accounting reserve, never above `STATE_DOCUMENT_CEILING_BYTES`. That
keeps refused-input accounting, delivery attempts and session ends writable. The bound follows
only the accepted rows, shrinks as they drain, and is unused outside an over-target transition.
The status record does not report this bound; the transition shows as over-100% utilization with
`pressure_state: hard_limit`. Local control schema `2.9.0`
carries custom counts, the
labels and that record. A client and service with different manifests are rejected at the
authenticated handshake, so both peers must run the `2.9.0` manifest to exchange them; there is
no down-conversion to `2.8.0`, whose status keeps the three-profile enum. An older revision that
reads a saved custom count treats it as malformed and drops that selection to the default without
reporting it. MCP status remains read-only and does not expose or change capacity.

`protect_next_reads` is a bounded request to retain read evidence linked to an obligation, claim
or finding; it grants no content or disclosure authority. `promote_buffered_observation` can retain
an individual native identity while its successful routine account remains buffered. It reports
historical content as `not_retained`; reacquired content is new evidence at a new state and time.
After the buffer is delivered, promotion reports `promotion_window_closed` rather than inventing
historical evidence.

The stages observed, buffered/retained, summarized, delivered and selected for a check are
distinct. Intentional detail omission is separate from non-replayable rejection. Bounded loss
ranges, their aggregate commitment and historical count survive current-pressure recovery.
Capture-ticket count and byte limits remain independent from structural capacity; partial or
unknown per-task backlog projections never assert complete workspace capture coverage.

FinishUP-owned tool observation follows ADR-022 decision 18 (issue #564). The hook ingress for every
host and the Codex stream reconciler recognize FinishUP's own tools under every host spelling
(`mcp__finishup__*`, `mcp__plugin_finishup_finishup__*`, `finishup:*`, `plugin-finishup-finishup:*`, and the bare
registry names), derived from the one registry tuple. Such an envelope is always ingested into the
bounded local observation store but is enqueued for delivery only as distinct evidence: an explicit
host failure or denial in either phase, or the post-event of `start`, `publish_work`, `check`, or
`respond`. The pre-event of every FinishUP-owned call and the post-event of a non-failed `status`,
`receipt`, or `read_guidance` stay local, and FinishUP-owned tool input/output is never captured as
content. Codex hooks are the paired carrier: `tool_call_id` is scoped to source, session, and
generation, and an orphan post retains `unpaired_event` until explicitly repaired. That sticky
record is disclosed coverage, not stale acquisition (issue #917): it stays on the observation
store, check coverage, `status` coverage and the receipt, through resume and service restart, but
it no longer raises the `observation_gap_or_stale` / `refresh_observation` advisory or keeps the
observation lifecycle `degraded`. The advisory names its live cause first in its evidence
references (`cause:<gap>` or `cause:lifecycle_<state>`). For source lag, a stale cursor, drain
backlog, service unavailable and vault locked, which recover in session, it clears when the cause
recovers. The unsupported-record codes (`unsupported_event`, `unsupported_format`) keep their
pre-#917 advisory: they do not clear in session, and classifying them as standing records is a
follow-up owned by #917/#913. Instead, the
first orphan in each new `(source, session, source generation)` scope queues one local
`UnpairedScopeNotice`; the next eligible hook `PostToolUse` context delivers it once ("FinishUP notice
(no response needed)"), and a delivered scope is not announced again, across restart. The notice
map is bounded at 256 scopes: to admit a new scope it forgets the oldest delivered notice, so only a
scope pushed out by 256 newer announced scopes can be announced again, and while all 256
retained notices are still undelivered no new notice is queued (the gap stays disclosed). The notice
is not a ledger record or finding, so it never counts as unanswered, never adds
`findings_unanswered` to closure readiness, and cannot be answered or supersede a check. A later
new scope gets its own notice. A recorded one-time acknowledgement of a notice waits for #905's
`acknowledged_not_done` disposition; until then no acknowledgement is requested, and the gap is
disclosed on the receipt whether or not the agent acts.
One host call is one ledger action (issue #917). A paired profile keys the pending action of an
individually delivered `PreToolUse` on the host call itself (`pre:<lane>:<session>:<generation>:
<correlation>:<family>`), which is the identity its `PostToolUse` action already used, so both
phases, and their hook and session-stream copies, name one action and one action event. Whichever
phase reaches the task ledger first records the action; the service appends the later phase
without the action draft only when the task ledger already projects that exact action event
(`projected_action_event`), so its result and captured evidence link to the committed action.
Both committed shapes stay lookup candidates, so replay after a lost acknowledgement, restart or
reattach resolves to the committed operation. A pre committed before this change keeps its
`pre-event:` identity and its operation digest, so its redelivery replays that operation and a
call spanning the upgrade keeps its historical second action instead of a third; history is never
rewritten. A Codex code-mode `exec` cell (the rollout `custom_tool_call` named `exec` and its
output) is a container that fires no hook, and the session-stream reader decides per cell. It
always keeps the cell's call row local, because whether the nested calls are hook-recorded is known
only later. It keeps the cell's output local too only when a Codex tool hook
(`PreToolUse`/`PostToolUse`, not lifecycle hooks) of the same host session was ingested after it
read that call and before the start of a complete stream pass that still did not see the output:
such a hook fired while the cell ran, so the nested calls' own hook rows are the ledger record of
the cell. A hook that could belong to the next cell (ingested after the output was written) never
counts, so every tool hook's own triggered reconcile is what settles it. It also keeps the output
local when every nested tool item the rollout wrote while the cell was open was one of FinishUP's own
MCP calls (an `McpToolCall` whose server is FinishUP's, or that names no server and a FinishUP tool, as
`later_material` reads it; issue #1038): the cell is then FinishUP's own call
whatever the hook timing. A FinishUP item counts only while its cell is the session's only open cell;
any other item, an uninterpretable row, or a FinishUP item read while several cells are open removes
that mark from every open cell of the session. The call and its output pair on their shared
`call_id` (Codex 0.159.3 also gives each row its own `ctc_`/`ctco_` `id`; `id` is only a fallback),
while a completed tool item keeps its own `id`. Otherwise the reader
delivers the output, which records the cell as its own action and result (the held call row adds
only content-free metadata), so a cell whose tools fire no hook (only `tools.update_plan`, for
example) is recorded whether or not other or later cells were hooked. Each cell's decision is
durable and replayed, and does not depend on the session's earlier hook history, so a read of the
call before its nested hook (a manual `finishup observe reconcile`, the session's first cell, or a
session the bounded map forgot) still keeps a hooked cell local once its hooks' own reconciles
complete. Per-session tool-hook stamps and per-cell decisions are bounded at 256 entries each; a
full map forgets the least recently active entry, which can only make an output deliverable. A cell
stored by the earlier count format is migrated, not dropped. Limits that remain disclosed: a cell
that mixes hooked and unhooked tools stays local, so its unhooked tool is not recorded; a tool hook
that lands while an unhooked cell runs (a late asynchronous hook, for example) can still keep that
cell local; a hooked cell keeps its own action beside its nested calls (a second record, never a
loss) when its call is read only after all of its nested hooks, when no complete pass ran between
its nested hooks and its output (a hook ingested without its reconcile, or a pass cut short by
backlog), when its hooks fired before an upgrade from the count format, or when the bounded maps
forget its entry before its output; a cell whose output never reaches the rollout (an interrupted
cell) keeps its call local and adds no record of its own; and a retained wrapper counts in the
local `observed_count` without an admitted, summarized or intentionally omitted bucket. A rollout `event_msg`/`item_completed` `CommandExecution`, `McpToolCall` or `FileChange` row
(event kind `item_completed`, issue #910) is a second copy of a hooked call under an id
(`exec-<uuid>`) that normally never joins the hook's call. Once tool hooks have fired for the
session it stays local with a wrapper's accounting unless it is the only carrier of a hooked
call's outcome: its id is an outcome-less hook call (it then corrects that `unknown` result,
ADR-022 decision 15), or it is a command item whose exit matches no unpaired stated hook post of the
same command commitment while an outcome-less hook call of that commitment is still unpaired (it
then records that call's exit as a second action). Pairing is counted per call, in arrival order,
so one call's stated outcome never withholds another call's only exit. Without tool hooks the row
is delivered with its `status`/`exit_code` outcome and its `command_commitment`. An `McpToolCall`
item with an `error` or a result `isError: true` fails whatever its `status`; a `FileChange` item
is an edit. The currently
installed Claude and Cursor native profiles are post-only carriers: their post observations never
diagnose a missing pre-event. A post with an actual tool-call identity, such as Claude's
`tool_use_id`, can materialize an observed action/result pair with a distinct post-only action
identity; it does not assert that a pre-event was observed. A generation-only Cursor post
materializes metadata-only evidence. Cursor `generation_id` is retained as metadata only and
never serves as a tool identity. A legacy false `unpaired_event` from a post-only profile may be
retired from the current projection only when retained history is complete and contains no true paired orphan; its gap
history remains auditable.
For FinishUP-owned calls, local pairing is unaffected, so a delivered post-event carries no
`unpaired_event` gap and
the service materializes its action from the post alone. No coverage gap is recorded: the service
already holds the authoritative record of every FinishUP-owned call it served. The same complete
host-spelling set gates advice delivery: without an explicit failure, a FinishUP-owned hook does not
lease pending recommendation context for the call being observed. An explicit self-call failure
remains eligible for pending advice as well as retention and delivery.

The local observation state also owns a sparse, one-shot `FrontierMotionNotice` per Codex session:
`from_sequence`, `to_sequence`, final `head_digest`, and exact accepted observation-record count.
Since issue #915 no hook peeks, delivers, or commits it (ADR-022 decision 11, amended): every
notice describes observation-authored motion, which leaves a held cooperative frontier admissible,
and motion by any other writer reaches the agent as `frontier_conflict` on its next state-sensitive
operation. The bookkeeping below is unchanged and describes the pre-#915 hook delivery; retiring it
is follow-up work. A newly accepted observation append creates the notice. Idempotent replay of a
completed append reconciles a missing pending notice from that append's committed frontier
metadata; a still-pending notice is coalesced rather than duplicated. After the hook consumer
receives the notice bytes, the store keeps that session's delivered high-water frontier
(`to_sequence` and `head_digest`), scoped to the announced task ledger. The coordinator binds every
candidate to the routed ledger's actual current frontier so an older completed-operation result is
still recognized as replay when the live head remains at or beyond the mark. An actual head below
the mark, or at the same sequence with a different digest, proves the stored lineage was rewound:
the mark and stale pending notice are discarded and announcement fails open from the new lineage.
Otherwise a later replay at or behind the mark is dropped and an overlapping candidate is clamped
so `from` and record count cover only the undelivered remainder. A mark recorded for a different
task never suppresses or clamps: when the session's mapping moves to another task, the stale mark
and any pending notice for the old task are discarded and announcements restart from the new
ledger's motion. The notice and delivered-mark maps persist per-entry recency ordinals, drop
ended-session entries first, and then evict the least-recently-used entry at their cap even after
restart. A legacy delivered mark missing digest/recency identity or another malformed stored value
is ignored as empty, failing open to a duplicate. Contiguous pending notices coalesce, and an
advice-safe `PostToolUse` hook consumes the exact notice only after emitting its bounded agent
context. If a later append merges into the pending notice between peek and commit, delivery
identity no longer matches; commit still advances the delivered high-water to the peeked
sequence/digest and clamps the merged remainder so the already-emitted range is not re-announced.
If the queued same-task notice instead proves the emitted frontier was rewound away after the peek
(a lower sequence, or the same sequence with a different digest), commit records no mark and leaves
the rewind notice queued so the new lineage's prefix is still announced. This context is
informational: it neither weakens exact-frontier checks nor expands the ADR-022 predicate that
permits a cooperative publish to retain a stale frontier across observation-authored records.

`hook_observed` (publication channel and artifact-observation class) and `harness_observed`
authorship require real observation evidence under an active consented observation arm — never a
trigger-only hook, consent marker, empty status, or degraded/stopped source alone.

Existing v0.1 ledger/object/import data remains readable without rewrite. Migration `0003` owns
encrypted observation-content/workspace-binding references, logical identity claims, exact-digest
trust, verification jobs/leases/results, and advice history/delivery state in addition to `0002`
consent/cursor/dedup/current-advice state. Migration `0004` owns inspection snapshots,
workspace→FinishUP-session routing, and session-scoped current advice without rewriting `0003`.
Migration `0008` adds nullable inner-content digest and byte-count bindings to content manifests
and inspection snapshots plus inspection redaction/truncation flags. NULL historical rows stay
readable but weak. None adds a plaintext content column.

### Maintenance

`MaintenancePort` has paired preview/execute methods:

- `preview_backup(BackupCommand) -> BackupPlan` and
  `backup(BackupCommand, *, confirmed_plan_digest,
  recovery_secret: RecoverySecret | None) -> BackupResult`;
- `preview_restore(RestoreCommand) -> RestorePlan` and
  `restore(RestoreCommand, *, confirmed_plan_digest,
  recovery_secret: RecoverySecret | None) -> RestoreResult`;
- `preview_migration(MigrationCommand) -> MigrationPlan` and
  `migrate(MigrationCommand, confirmed_plan_digest) -> MigrationResult`.

Shared types are `MaintenanceLocation`, `MaintenanceKind` (`backup`, `restore`, `migration`),
`BackupMode` (`machine_bound`, `portable_recovery`), `MaintenanceReason`, `MaintenanceError`,
`MaintenanceHandle`, `MaintenancePin`, `BackupObjectEntry`, `PrivacyAuditBackupSnapshot`, `BackupManifest`,
`BackupCommand`, `BackupPlan`,
`BackupResult`, `RestoreCommand`, `RestorePlan`, `RestoreResult`, `MigrationCommand`,
`MigrationPlan`, `MigrationResult`, `RecoveryOperation` (`create|restore`),
`RecoverySecretAcquisition`, `RecoverySecretAcquirer`, and `RecoverySecret`.
A preview is read-only;
execution recomputes every material fact under the current generation and requires the exact
confirmed plan digest. Backup uses one pinned frontier and an online SQLite snapshot; restore
builds and verifies a new quarantined route before one catalog CAS; migration is backup-first and
never rewrites canonical event bytes. A migration target equal to the current version is rejected as
an invalid/no-migration request; v0.1 does not fabricate backup/replay identities or widen the frozen
plan/result schemas to represent a no-op. Downgrades and skipped versions remain rejected.

The maintenance pin and backup manifest bind privacy-root generation/digest. The backup contains a
canonical structural `privacy-audit-snapshot.json` sidecar plus every referenced encrypted
task-bundle object, without creating ledger inventory rows. A same-installation route switch copies
and verifies the current catalog root union and CASes its generation/digest. Clean-profile restore
imports terminal audit evidence, expires pending/approved/authorized state, resolves
`receipt_pending` as `transport_failed/outcome_unknown`, and never restores live disclosure
authority.

`ports/maintenance.py` owns the service-internal `MaintenanceHandle`; the SQLite maintenance
adapter is its sole concrete constructor after a durable generation CAS, and every consumer
revalidates its task/request/route/generation/plan bindings. `MaintenanceService` owns support
request validation and explicit confirmation. Its exact generation-bound constructor injects
`MaintenancePort`, `ClockPort`, `MaintenanceDiagnosticSink`, the least-authority
`RecoverySecretAcquirer`, whose sole method is
`acquire_recovery_secret(RecoverySecretAcquisition) -> RecoverySecret`.
`RecoverySecretAcquisition` is the frozen, secret-free tuple of exact request ID, confirmed plan
digest, current positive service generation, and `create|restore` operation. The acquirer accepts
no raw secret, `str`, `bytes`, mutable buffer, location, command, or general maintenance authority;
it may return only the opaque one-shot `RecoverySecret` for that exact binding. Its shared values
are maintenance request values, `Confirmation`, and `ConfirmationChannel`.
`ConfirmationChannel` is exactly `interactive|noninteractive_flag|release_automation`. Every
channel requires the exact current plan digest plus explicit acceptance; a bare/general `--yes`
never suffices. Only after `Confirmation.plan_digest` equals the returned preview's current
`plan_digest` and explicit acceptance is true may `MaintenanceService` construct the acquisition
and call the acquirer. Portable-recovery execution additionally requires the foreground
confidential helper after confirmation, so it fails closed in noninteractive v0.1 environments;
machine-bound maintenance never calls the acquirer and may use either reviewed automation channel.
MCP exposes no maintenance method.
The constructor's positive `service_generation` is the owning daemon instance generation, not a
caller/request field, and is copied only into a confirmed portable `RecoverySecretAcquisition`.

### Harness integration

`IntegrationsPort` methods are `preview_skill`, `install_skill`, `status_skill`, and
`remove_skill`, each taking an exact `HarnessId` plus its command value. The port names the
capability, never one harness; Codex is the first adapter, not the definition (ADR-010).
Shared types are `HarnessId`, `HarnessProfile`, `HarnessHookProfile`, `IntegrationScope` (only `trusted_project`),
`IntegrationAction`, `IntegrationState`, `IntegrationReason`, `IntegrationTarget`, `SkillSource`,
`IntegrationFile`, `SkillPreviewCommand`, `SkillApplyCommand`, `SkillStatusCommand`,
`IntegrationPreview`, `IntegrationStatus`, `IntegrationResult`, and `IntegrationError`.

For the Codex skill, `managed_marker_valid` means the complete installed tree matches its own
recorded inventory; it does not mean the tree matches the currently shipped skill. An intact
older tree stays `modified` against the current source and carries preview warning
`owned_skill_update`. Ordinary reviewed install and remove may replace/remove that owned tree;
unrecorded edits still require the existing explicit replacement authority. The preview digest
binds all installed files and the marker, including members no longer shipped by the current
source. No wire enum or marker schema changes. Claude Code and Cursor retain their independent
marker-consistent plugin update paths.

`HarnessId` is a closed enum whose membership is exactly `claude|codex|cursor`. `HarnessProfile` is the
frozen per-harness descriptor: `harness_id`, `skill_root` (the exact relative install directory),
`frontmatter_profile` (the harness's required skill-header shape), `capability_profile_ids`,
`supported_versions`, and `hooks_by_capability_profile: Mapping[str, HarnessHookProfile | None]`.
All three support collections may be jointly empty only for the explicit unprofiled/unadvertised
state. Otherwise capability profiles and supported versions are nonempty and the map has exactly
the same keys as `capability_profile_ids`; missing, extra, wildcard, inherited,
or range-derived entries are invalid. A v0.1 exact cell may select a trigger arm, an observation
arm, both, or `None` after E-013 passes. For first-party Codex, observation is a required v0.1
capability once the exact cell is capability-proven; unproven or unprofiled cells keep
`observation_events=()` and cannot emit `hook_observed` (ADR-005, ADR-010).

The frozen v0.1 service operations `integration_preview` and `integration_execute` remain
Codex-only despite `HarnessId` containing `claude|cursor`: their required `harness` discriminator is
exactly `codex`. Cursor and Claude lifecycle operations use separate host-native artifact surfaces
and path-explicit CLI adapters; they are not routed through `IntegrationsPort` or those service
methods.

`HarnessHookProfile` is the closed descriptor
`(trigger_event, trigger_payload_profile_id, evidence_case_ids,
trigger_action="reground_status", duplicate_policy="coalesce", loop_policy="single_flight",
failure_policy="best_effort", observation_events)`. `trigger_event`, payload profile, evidence case
IDs, and each `observation_events` member are exact nonempty bounded identifiers from the selected
capability cell when that arm is declared; no wildcard or version range is allowed.
`observation_events` may be nonempty for first-party Codex when capability-proven; otherwise it is
exactly `()`. It distinguishes two arms. An **observation hook** reports what the harness saw the
agent do and is the only arm that earns `hook_observed`, and only when real observation evidence
exists. A **trigger hook** fires on a harness lifecycle event — context compaction is the
motivating case — and prompts the agent to re-ground by calling `status`. A trigger hook earns no
coverage: it observes nothing, and the `status` result it causes discloses only what that call
would already have returned under the ordinary provenance rules and the `agent_context` ceiling
("Privacy policy, disclosure, and outbound gateway" above), so it touches no coverage lattice value
and changes no honesty wording. E-013 must freeze the exact event, payload/privacy boundary,
coalescing/loop guard, gap codes, and failure behavior before one exact v0.1 capability cell
declares either arm. Cells without that evidence remain `None` or keep `observation_events=()`.

Adding a first-party harness is exactly one `HarnessId` value plus one adapter under
`adapters/integrations/`; it requires no change to this port, to `IntegrationService`, or to any
guidance content. The guidance a harness installs is owned once, harness-neutrally, under
`guidance/` and is not duplicated per harness. A harness FinishUP has not profiled is still fully
supported through the MCP baseline and identifies itself as `cooperative_agent` (§6); first-party
integration buys harness-native ergonomics and, when observation is capability-proven and
consented, stronger coverage — never a different public contract.

`IntegrationService` owns request validation and confirmation. Install/replace/remove are bound to
a freshly recomputed preview digest and explicit acceptance. Its shared values are
`IntegrationRequest`, `IntegrationStatusRequest`, `IntegrationConfirmation`,
`IntegrationDiagnostic`, `IntegrationDiagnosticSink`, and the exact
confirmation channel `interactive|noninteractive_flag`. Noninteractive execution requires both
the exact preview digest and explicit acceptance; a generic `--yes` cannot stand alone. Modified,
partial, unmanaged, unsafe, or changed-after-preview copies are preserved. v0.1 writes only the
profile's exact `skill_root` — `.agents/skills/finishup/` for `codex` — inside one explicitly supplied
trusted project; it never edits harness/MCP configuration, Git state, package resources, or
arbitrary skills. Existing `.agents` and `.agents/skills` parents must be real owner-controlled
directories: a symlink at either component is `target_unsafe`, creation/replacement/removal use
directory-fd no-follow operations, and a parent identity change between preview and apply is
`preview_stale` (issue #396).

Filesystem presence and capability compatibility are independent facts: an unprofiled source is
`unsupported`, while its destination state remains `absent|installed_exact|modified|partial|unsafe`
rather than being rewritten to `incompatible`. The standalone integration service still refuses an
unprofiled install. ADR-012's accepted first-run setup is the one narrow exception: it may install
the same preview-digest-bound packaged bytes into the already approved trusted project so Codex can
discover the project skill, while reporting compatibility `unsupported` and automatic activation
untested. Prompt and non-prompt setup surfaces compute the project-skill preview before acceptance;
non-prompt front ends echo the MCP, skill, and plugin-activation preview digests, and any stale
digest refuses the whole apply before a file is written. Setup separately reports
`project_skill_installation`, structural plugin-source installation, `plugin_activation`, MCP
registration, hooks/consent, service routing, and AI-powered review readiness; none of those
fields implies
another. `plugin_activation` uses the closed state
`active|installed_not_activated|not_installed|foreign`. `not_installed` is actual source
absence only. A byte-present plugin tree that is not a current renderer variant — including
`installed_untrusted_unknown` / modified copies that Codex may still be serving — is
`installed_not_activated`, never `not_installed` and never `active` (issue #347). When an explicitly supplied Codex home is
bound, the registration and readiness `plugin_activation` blocks echo that home and its config
path even when the activation preview or inspection fails, and they carry the actual failure
reason; `codex_home_required` appears only when no home was provided. Readiness facts that were
not observed (`marketplace_registered`, `plugin_enabled`) are reported as null, never asserted
`false`. Its preview/inspection/application bind the
exact selected executable path and SHA-256, an owner-supplied existing absolute non-symlink home,
the parsed result of exact `--version`, repository marketplace and selected-home config
preimages/proposals, installed managed source-tree digest, cache root
`<home>/plugins/cache/finishup/finishup` and cache preimage/intended tree digest, and exact post-consent
`plugin list --marketplace finishup --json` and `plugin add finishup@finishup --json` commands. Preview runs
the version probe with both home variables set to a fresh owner-private temporary home, removes its
scratch afterward, and performs no selected-home inventory read. After consent, apply forces both
home variables to the approved home, re-probes under its lock, and CAS-fences each write. A later
failure preserves approved partial marketplace/config/cache state for retry and performs no
pathname rollback that could race a concurrent replacement.
`active` additionally requires canonical inventory to report the expected repository plugin
installed and enabled and its installed-version cache tree to match the host-specific render of
the managed source; marketplace/config presence alone remains `installed_not_activated`. This is
standing trust for future sessions, not proof that a session loaded a hook or delivered
observation evidence.
The managed project-tree source is always the canonical async-free render; the exact activation
probe version selects only the cache-layer render. Pure-ingress command
hooks use `"async": true` only from Codex `0.148.0-alpha.6`; older, missing, malformed, or
oversized versions use the bounded synchronous form because affected Codex hosts otherwise discard
the handlers. The cache-layer render also binds `.mcp.json` to the proven absolute launcher of
this runtime — the same console script the external registration writes; `PATH` is not consulted —
and, when this process is isolated, sets both `FINISHUP_ISOLATED_ROOT` and `YOETZ_ISOLATED_ROOT`
to that root (issue #1076, ADR-026, ADR-028). The project source `.mcp.json` and the committed
repository tree stay the portable bare `finishup` command with no environment. A marker-consistent
cache whose `.mcp.json` still names a bare `finishup` or a legacy `yoetz` command is a prior
managed render: the next activation preview plans a whole-directory replacement, and apply writes
the bound entry. Repeating that activation is a no-op. Removal deletes the cache, including the
bound entry, and leaves the portable project source in place. Plugin hook commands in the
cache, the project source, and the committed tree are not bound: they stay the portable
basename `finishup` with no environment. Codex hook trust hashes that command, and the hook
schema has no environment field, so activation does not rewrite cache hook commands onto the
proven launcher. A legacy `yoetz` hook string is replaced only when activation recopies the
current portable source, which still names `finishup` by basename. Apply seeds the versioned cache with the exact previewed host-rendered bytes
(`plugin add` copies the canonical source, and apply then replaces that marker-identified copy in
one atomic whole-directory swap) and verifies the result against the bound install digest. A cache
tree that carries a valid `yoetz.codex-plugin-install/1` marker and byte-matches that marker's own
inventory is a prior finishup-managed render: preview classifies it as replaceable, binds its digest
as the cache preimage, and apply atomically replaces the whole directory (same-version refresh).
`destination_conflict` remains reserved for foreign, marker-inconsistent, or modified cache trees,
and a cache that changes between preview and apply still refuses as `preview_stale`. A project
source tree that byte-matches its own valid marker (for example a prior host-rendered or
older-guidance render) is likewise a replaceable managed render, not a `modified_copy`; apply
still requires a byte-exact current renderer variant at its source fences before any mutation.
MCP server registration is a sibling port, never an `IntegrationsPort` overload (ADR-012).
`HarnessMcpPort` methods are `status_registration`, `observe_registration`, `preview_registration`,
`apply_registration`, `preview_unregistration`, and `apply_unregistration`, each taking a
`HarnessBinary` (harness ID, redacted-repr executable path,
optional reported version, `supported|untested` compatibility). Shared names are
`MCP_SERVER_NAME` (exactly `finishup`; `MCP_LEGACY_SERVER_NAME` `yoetz` is read, never written,
ADR-048), `MCP_SERVE_COMMAND` (exactly
`("finishup", "mcp", "serve", "--host", "codex")`), `MCP_STRICT_SERVE_COMMAND` (exactly
`("finishup", "mcp", "serve", "--host", "codex", "--semantic", "off")`),
`McpRegistrationState` (`absent|yoetz_owned|foreign_present`), `McpRegistrationAction`
(`register|reregister|unregister|noop`), `McpRegistrationReason` (`confirmation_required|preview_stale|
harness_unavailable|parse_failed|timeout|registration_failed|foreign_entry_present|isolation_invalid`),
`McpRegistrationPreview` (including the exact proposed `isolated_root` or null),
`McpRegistrationObservation`, `McpRegistrationCommand`,
`McpRegistrationResult`, and
`McpRegistrationError`. `McpRegistrationObservation` carries `harness_id`, `state`,
`route_profile` (`policy|strict|null`), and `isolation_binding`
(`ambient|isolated_exact|missing|different|null`), plus optional internal `serve_command` carrying
the exact observed owned argv for the applied-route record; route and binding are non-null only when the
state is `yoetz_owned`, because a foreign or absent entry has no FinishUP route to describe.
`observe_registration` reads exactly what `status_registration` reads, mutates nothing, and shares
its `status` diagnostic phase. Each observation starts with `codex mcp get finishup --json`; because a
nonzero named lookup is not positive absence, it falls back to bounded `codex mcp list --json`.
Only a successful list with no matching name classifies as `absent`; a failed/malformed list or
duplicate matching names raises a typed error, while one matching entry is classified normally.
The bounded parser also rejects duplicate JSON keys, nonstandard constants, and truncated output.
Codex exposes no compare-and-add token, so the port cannot claim atomic exclusion of a
non-cooperating configuration writer inside the final accepted-add subprocess window.
The observation exists because both owned serve commands classify as
`yoetz_owned`, so state alone cannot distinguish a strict registration from a policy one.
`HarnessMcpService` owns confirmation
(`McpRegistrationConfirmation` with channel exactly `interactive|noninteractive_flag`) and
diagnostics (`McpRegistrationDiagnostic`, `HarnessMcpDiagnosticSink`); every registration
mutation is digest-bound to a freshly recomputed preview, a foreign same-name entry is
preserved without any force path, and success is verified by re-reading state. Unregistration is
the same digest-bound lifecycle for an owned external registration: `preview_unregistration` /
`apply_unregistration` re-read the current entry immediately before the name-based
`codex mcp remove finishup`, run it only when the observed argv is still the exact previewed FinishUP
serve command, refuse an observed foreign replacement, and treat an already-absent entry as
`noop`. Because Codex 0.149.x exposes no compare-and-remove token, an owned-entry preview carries
`host_remove_not_compare_and_swap`; callers must quiesce concurrent host configuration writers,
and the port does not claim atomic exclusion inside the final host subprocess window. The same
positive-absence fallback is required after removal, so a generic failed named lookup never proves
success. After a returned nonzero remove exit, the adapter still performs that bounded read-only
probe once. Verified absence returns `UNREGISTER` with the fixed warning
`host_remove_returned_nonzero`; no mutation is retried. `McpRegistrationResult.warnings` carries
that token to the CLI and setup disconnect. Their nested `removal` / `status.mcp_removal` report
uses `yoetz.mcp-removal/1` (`schemas/integrations/mcp-removal-1.0.0.schema.json`): `completed`
requires `state_after=absent`; `unverified` carries an observed present state or null and
`next_action=inspect_registration`. A mutating command exception or unreadable post-state remains
`REGISTRATION_FAILED`. The CLI retains exit 20 and emits an exact runtime/home/binary-bound status
continuation; it does not treat a failed lookup as absence. Only verified absence clears applied-route
bookkeeping and permits subsequent cleanup. Successful zero-exit removal has no result warning.
This is a client-local report; it adds no MCP tool, hook event, ledger receipt field, or TUI operation.
The interactive approval surface prints the exact command, route, isolated root, warnings,
and preview digest. The preview binds the exact command, `policy|strict` route profile, and exact
ADR-026 isolated root when present. Ambient external registrations carry no environment. Isolated
external Codex registrations carry exactly two native `--env` pairs naming one root,
`FINISHUP_ISOLATED_ROOT=<validated-root>` and `YOETZ_ISOLATED_ROOT=<validated-root>` (ADR-048, so a
pre-rename launcher found through `PATH` still isolates); an entry with either name alone or both
equal reads as the same binding and re-registers to the two-name form, two different values are
not FinishUP's; a missing root is re-registration drift, as is a different
known root on a legacy bare registration,
while any arbitrary key, inherited-variable declaration, or malformed root makes the same-name
entry foreign and preserves it. The legacy `yoetz` key is read in the same observation and
reported as `legacy_registration` (ADR-048 §3). The route profile is
explicit input:
`finishup setup run` and `finishup integrate <harness> mcp preview|install` accept
`--route-profile strict|policy`. Without that input, an existing finishup-owned registration keeps
its observed profile — no configuration derivation (or derivation-on-exception fallback) may
rewrite a previously chosen route — and only a fresh registration falls back to strict
(zero-egress wizard) or the structural configuration derivation (`integrate`). A route transition
is surfaced before mutation: the wizard preview and report carry `route_profile_before` next to
`route_profile`, and changing an existing owned route requires the explicit input plus the
ordinary digest-bound re-registration.
The setup-wizard
schema tokens are `yoetz.setup-wizard-marker/1`, `yoetz.setup-wizard-report/1`,
`yoetz.setup-status/2`, `yoetz.mcp-registration-preview/1` (ambient) / `2` (isolated) / `3`
(installed absolute launcher), and `yoetz.mcp-unregistration-preview/1` (ambient) / `2`
(isolated) / `3` (installed absolute launcher); the marker lives at
`state_dir()/setup-wizard.json` via
`config.paths.setup_marker_path`. The CLI surfaces are
`finishup setup run|status` and
`finishup integrate <harness> mcp status|preview|preview-remove|install|remove` (ADR-012).

The #767 desktop entrypoints are `setup run|status|disconnect --host
codex|claude|cursor-ide|cursor-cli`, with `--host-path`, `--host-config-root`, and `--project`
overrides. `setup-status/2` adds the executable-backed `hosts` inventory and Claude activation
posture alongside its legacy Codex `discovered` rows. Inventory is not connection proof. The CLI
envelope is version-tagged for compatibility and is owned by
`schemas/integrations/setup-status-2.0.0.schema.json` with the representative
`fixtures/integrations/setup-status.case.json` vector. The `/2` tag leaves the historical
unversioned status shape outside the released contract.
`yoetz.host-connection-plan/1` binds
the request, installation, project, route, adapter previews and changes to `preview_digest`.
`yoetz.host-connection-report/1` names `preview`, `completed`, `unchanged`, `status` or `incomplete`,
with the plan, layer-specific status, reason and continuation where applicable.
`connection_observed: false` means setup did not observe a native session. An agent repeats the
preview's exact `--request-id` and `--preview-digest` with `--accept`; generic acceptance cannot
bind unseen changes. Human and agent surfaces share that application path. ADR-012 specifies
compound-review consumption and the separate observation/provider/disclosure authority.

For issue #654, `mcp_command_profile` validates the shape of a bare or absolute console-script
command with the exact current or legacy Codex serving suffix; it establishes no ownership.
`adapters/integrations/codex_launcher.installed_launcher` supplies the adapter's ownership proof:
the console script in the current interpreter's scripts directory must match exactly one SHA-256
and size entry in that runtime's installed FinishUP RECORD. The executable and its ancestors must be
non-symlink, owned by the current user or root, and not writable by group/others. For a pinned
runtime, the validated root, instance identity, pin, lifetime, package version, and runtime prefix
must agree. An absolute registration is owned only when its exact launcher matches that proof,
its serving suffix is recognized, its transport is unambiguous and enabled, and its environment
contains no unreviewed binding. A different root on an absolute registration is foreign, not a
repair target. No candidate from host configuration is executed to establish this proof.

New previews prefer that proven absolute console script. An installed CLI without valid proof
refuses registration instead of falling back to PATH; embedded callers without an invoking launcher
retain bare-command compatibility. Existing bare and legacy registrations remain recognizable for
removal or an explicit migration to the absolute current command. Absolute preview digests bind the
launcher bytes and proposed command/root; registration also binds the observed command/root so drift
invalidates approval. Applied-route records preserve the exact observed argv, including its absolute
launcher; their command validator checks shape, never confers ownership. Older records remain
readable, and an older reader that cannot parse an absolute record retains its existing fail-soft
missing-record behavior. CLI and terminal previews display that exact argv; provider status and
preflight consume the shared ownership observation. This changes no workflow request/result schema,
hook contract, or receipt format. The proof is installation-local integrity, not authentication
against a machine owner who can rewrite both the installed script and RECORD. Standalone `finishup
provider endpoint` retains its explicit credential next command. When endpoint binding is embedded
in the composed setup wizard, that standalone handoff is suppressed because the wizard still owns
privacy consent and confidential ingress. Every visible yes/no prompt near credential setup says
that API-key entry has not started and accepts only yes/no; a separate heading announces the hidden
trusted-console ceremony. Invalid visible-prompt input is never reflected by FinishUP. Provider
credential failure reasons cross the report boundary only through a fixed nonsecret allowlist, while
provider binding, credential storage, repository privacy, service state, and AI-powered review
readiness remain independent report components. Recovery commands are derived from the read-only
committed/live status when available, with component results used only as a state-equivalent
fallback, so failure in a later component cannot rewrite an already committed privacy grant. `setup
status` rows carry `registration_state` and `registered_route_profile`; the `integrate <harness> mcp
status` body carries `state` and `route_profile`.

**Host admission port (`adapters/integrations/host_admission.py`, issue #467).** `HostAdmissionState`
is `absent|present|partial|foreign|unknown`; `HostAdmissionAction` is `grant|revoke|noop`;
`HostAdmissionReason` is `confirmation_required|preview_stale|foreign_entry_present|
entry_unreadable|route_not_policy|route_unobserved|codex_binary_inconsistent|grant_not_permitting|
grant_unverifiable|owner_required|target_unsafe|write_failed|host_invalid`. `observe_host_admission` reads only the
host's project-scoped surfaces and classifies by exact entry: Claude `mcp__finishup__check` for an
external registration or `mcp__plugin_finishup_finishup__check` for the plugin-owned route in
`permissions.allow` (detail `allow`) or `ask` (detail `ask`);
Codex the byte-exact `[mcp_servers.finishup.tools.check]` / `[plugins."finishup@finishup".mcp_servers.finishup.tools.check]`
table with `approval_mode = "approve"` (detail `external|plugin|both`); Cursor `finishup:check` in
`mcpAllowlist` (case-insensitive) and `Mcp(finishup:check)` / `Mcp(plugin-finishup-finishup:check)` in
`permissions.allow`. A deny rule, a wider rule (`deny_rule_present`, `wider_rule_present`), a
non-exact table (`entry_not_exact`), a Codex server-level default (`server_default_present`), or
the tool in both `allow` and `ask` (`allow_and_ask_present`) is `foreign`; a symlinked, oversized,
unparseable, or wrongly shaped file (including JSON `null` where an object or list is required) is
`unknown` (`file_symlink|file_too_large|file_unreadable|
file_invalid|shape_invalid|file_not_regular|folder_not_owned`). Every operation judges the project
root by the shared project-root rule (`config.foreign_write.project_root_admitted`, ADR-007
2026-10-14). Each surface is read through its host folder (`.claude`, `.codex`, `.cursor`) opened
without following a link: a folder that is the user's own or root's and that no other account can
write is read normally; any other folder is `unknown` with detail `folder_not_owned`, so status,
previews and the reverse sweeps never read another account's folder as this user's admission, and a
host folder root committed is read normally by host admission (typically `absent`; every Claude
Code plugin change (install, update, enable, disable, remove; status still reads it) and Cursor's
project MCP status, connect and disconnect still refuse such a folder, ADR-007 item 5's known
gap). A preview that would change a surface requires its folder
to be the user's own and unshared (`target_unsafe` otherwise); apply pins the project root and host
folder by descriptor, creates an absent folder `0700`, and stages, rechecks, renames and unlinks
relative to that descriptor. `preview_host_admission` refuses a grant unless the
caller's exclusively observed owner is `external|plugin`, its route is `policy`, and the observed
grant permits review (`None` is unread and
refuses), refuses both actions on `unknown`, refuses a grant on `foreign`, and binds the
`yoetz.host-admission-preview/1` digest over host, action, owner form, checkpoint, every entry
observed, and the SHA-256 of every file it would write. `apply_host_admission` recomputes the
preview, rechecks each exact byte preimage immediately before mutation, and refuses `preview_stale`
on pre-mutation drift. It writes each surface atomically (`0600`, created folder `0700`, file or
folder link refused), deletes a file that held nothing but a FinishUP entry, and re-reads and
verifies the resulting state. A mutating preview carries `host_config_not_compare_and_swap`:
ordinary host files cannot exclude a non-cooperating same-UID writer in the final syscall window,
so callers must quiesce host configuration writers during apply; a conflict after an earlier
surface changed is `write_failed`, not an atomic rollback claim. For Codex, an exact table belonging
only to the inactive owner does not make the active owner `present`; grant adds the applicable
table. For Claude, a grant whose exact entry already sits in the other list is a mode change:
preview moves the entry between `allow` and `ask` under the same digest-bound preimage recheck;
only a grant whose requested mode is already set is `noop`. Revoke needs no route, grant, or
current owner and removes every exact external/plugin form FinishUP can write.
`sweep_host_admission` is the reverse transition (outcome `removed|absent|retained_foreign|
unknown|write_failed` per host) used by the privacy ceremony, `integrate <host> plugin remove`,
strict plugin re-renders, `integrate codex plugin remove`, `integrate codex mcp
install|remove --project-root`, and `setup disconnect --host <host>` for its `--project`; each
reports it as `admission_cleanup` and its preview discloses the same, including when the primary
MCP registration action is already a `noop`. A disconnect plan lists the change token
`remove_project_admission`; because the released `yoetz.host-connection-plan/1` body is closed,
the cleanup detail (`admission_cleanup`: per-surface state and file digest, plus `legacy_entries`
naming exact pre-rename entries, ADR-048; an otherwise `absent` surface holding only those still
plans the sweep, while a `foreign` surface never does: the sweep never edits one, so
`admission_cleanup_needed` counts `legacy_entries` only on an `absent` surface, as
`cli/host_admission.admission_cleanup_preview` does) and, for Codex,
`admission_other_projects` travel in the preview report's `status` and are folded into
`preview_digest` (a grant or revoke after preview makes the plan stale). Apply sweeps before any
registration removal; a sweep that ends `unknown|write_failed` stops the disconnect as
`connection_admission_cleanup_failed` before anything else changes; an `unknown` surface (or an
unreadable observation) refuses the same way when the plan is prepared and again before the sweep,
whatever else the surfaces hold, with `status.admission_unreadable_surfaces`. Codex additionally
projects the project's `.codex/config.toml` after the sweep (`codex_mcp.project_transport_dependence`
`none|depends|unknown`; `after_sweep` strips the exact FinishUP and legacy tables only from a
surface the sweep edits, `host_admission.codex_sweep_edits(raw)`: `present`, or `absent` with exact
legacy entries, so a foreign surface is modeled unchanged): when it removes the user-level
transport and `depends`, preparation refuses `connection_project_mcp_tables_retained`
(`status.project_mcp_retained`); when the unregistration also removes an owned entry under the
earlier `yoetz` key, `mcp_servers.yoetz` tables count too (`names`), after the exact legacy tables
are swept. Other projects
whose layer `depends` (or is `unknown`) keep the transport: `status.admission_other_projects`
entries carry `project_root`, `dependence`, and a revoke `next_command` only when exact FinishUP
tables alone remain; warning `mcp_registration_kept_for_other_projects`; a bound of 32 inspected
candidates (after filtering missing and same-directory ones) is reported as
`admission_other_projects_known|_inspected` with warning `other_projects_partially_checked`, and
an incomplete read keeps the transport (`--remove-shared` refuses). `setup disconnect --remove-shared` (disclosure
`remove_shared: true`, carried by the continuation) removes the shared pieces for every project and
refuses `connection_other_projects_need_registration` while one still depends. Codex reports
`status.project_config_load: loads|fails|unknown`; `fails` is
`connection_project_config_unloadable`. `codex_mcp.codex_project_mcp_leftovers(home, project)` reads
both server keys, `finishup` and the earlier `yoetz` (whose exact `[mcp_servers.yoetz.tools.check]`
a Yoetz 0.2.x `integrate codex admission grant` wrote and a Yoetz 0.2.x disconnect left behind,
ADR-048), and names each key whose project table has no `command` or `url` in the project or the
user layer; a key is `tools_only` when only exact approval tables remain on a file the revoke
edits, otherwise `retained_tables`. `project_mcp_leftover` is `retained_tables` when any key is,
`project_mcp_leftover_servers` lists every key, and `project_mcp_leftover_retained_servers` and
`project_mcp_leftover_tools_only_servers` list them by kind (#1073), so the step never calls an
exact FinishUP table one the owner edited. The continuation (`next_command`) is the admission
revoke whenever a key is `tools_only` (also beside an edited `yoetz` table: the revoke removes the
exact table and leaves the edited one), else the reconnect for `retained_tables` under `finishup`
alone, and none for a retained `yoetz` table (FinishUP no longer registers that key; the step
names the file to edit). While it loads, status adds `project_mcp_needs_registration` when the
tables need the transport, counting `yoetz` tables while an owned `yoetz` registration supplies
them (the observed `legacy_registration`, or statically a FinishUP-shaped entry,
`codex_mcp.legacy_registration_shaped`). `setup status --host codex` and every failed Codex setup
command report such a leftover.
An owned `yoetz` registration migrates on connect only while no project still needs it (#1073):
`CodexMcpAdapter` reads `codex_mcp.legacy_registration_dependents(home)`, a
`LegacyRegistrationUse(needed_by, unreadable, unread)` (properties `kept_for`, `unchecked`,
`keeps`). It reads every project of `codex_mcp.home_project_candidates(home)` (trust rows plus
verified members, including the Yoetz-era bound project; no count window: each project file is a
bounded 64 KiB read, and the user `config.toml` is read within Codex's 1 MiB bound). `needed_by`
are projects whose readable `.codex/config.toml` names `mcp_servers.yoetz` without a transport of
its own (such as the exact table a Yoetz 0.2 admission grant wrote); `unreadable` are those whose
file cannot be read safely (`codex_mcp.project_config_unreadable_reason`: `symlink`,
`not_regular_file`, `oversized`, `unreadable`, `not_valid_toml`); `unread` are closed tokens
(`ports.harness_mcp.LEGACY_UNREAD_REASONS`: `user_config_unreadable`,
`connected_projects_unreadable`, named only when the user config itself was read, and
`project_path_unsafe` for a known path holding a control character, which is never read, returned
or echoed). Any of them keeps the entry beside `finishup`: the preview action writes only the
`finishup` key (`noop` once it is current), carries warning `legacy_registration_kept` and
`legacy_kept_for`, `legacy_kept_unreadable`, `legacy_kept_unchecked` (`bool(legacy_kept_unread)`),
`legacy_kept_unread`, and binds them in the digest (`/6`); apply never removes the kept entry. The
Codex connect plan then has no `migrate_legacy_mcp_registration`, adds warning
`legacy_registration_kept`, and discloses (`codex_connection.legacy_kept_disclosure`)
`legacy_registration_kept_for` (entries `project_root`, `dependence`, the revoke `next_arguments`
when only exact earlier-name approval tables hold it, and `unreadable` with its reason for an
`unknown` one), `legacy_registration_codex_home`, `legacy_registration_kept_unchecked` and
`legacy_registration_kept_unread`, plus the explicit way out (`codex_connection.legacy_way_out`):
`mcp_removal_preview_arguments` (`integrate codex mcp preview-remove --codex-path --codex-home`,
whose `remove` form with `--accept --preview-digest` removes the registration under both names)
and `reconnect_arguments` (`setup run --host codex --host-path --host-config-root --project`, or
the low-level `integrate codex mcp install --codex-path --codex-home` for that path). Connect
status reports the same, read now, while the observed entry is owned. Every structural
`<name>_arguments` in a status or disclosure renders as `<name>_command`
(`cli.host_connection.rendered_status`). `cli.host_connection.legacy_kept_lines` words it: per
project the revoke, what makes an unreadable file readable (or the trust entry to remove), or the
edited tables to remove; the unread inputs and their fixes; "After those revokes, connect again"
only when the revokes are all that hold it; and the way out, saying every project loses FinishUP
until one connects again and a project still naming the removed server stops loading until those
tables go. A connect after that migrates; a disconnect removes both owned keys only when no project
needs either (its `admission_other_projects` check counts `yoetz` tables while the owned entry
exists). When the kept entry serves another review mode than the requested one
(`legacy_route_profile`, warning `legacy_registration_route_kept`), every front end stops before
any change: `setup run` refuses `connection_legacy_registration_route_kept` (status
`route_profile_before`, `route_profile`, the kept facts, the way out on the requested mode, and
`keep_route_arguments` for the same command on the kept mode), the terminal interface blocks before
the approval, the shared integration step (wizard and both applies) fails with that reason and a
`next_step` built from the selected executable, Codex home and project, and `integrate codex mcp
install` exits 2 with `mcp_registration_legacy_registration_route_kept`, naming its own `install`
rerun on each mode. The wizard approval and `integrate codex mcp preview|install` name a kept entry
(the step's success result carries the lines as `next_step`; the low-level results carry the
rendered facts). TUI `IntegrationPlan` adds `legacy_registration_kept_unread` and
`legacy_registration_kept_lines` (rendered on the approval screen); menu and readiness words
distinguish "a project's Codex settings still use it" from "not every project of this Codex home
could be read". The disconnect's `_other_projects_needing_transport` treats an `unread` input like
its 32-project bound: `admission_other_projects_unread` (closed tokens) keeps the transport on an
ordinary disconnect, says which input and what makes it readable, names the way out
(`mcp_removal_preview_arguments`), and `--remove-shared` refuses
`connection_other_projects_need_registration`.
Several projects per host configuration root (ADR-012, 2026-10-14, #1058): the record
`<config root>/.yoetz-connected-projects.json` (`host_projects.CONNECTED_PROJECTS_FILE`, a frozen
literal that does not follow `MCP_SERVER_NAME`; canonical JSON `{"projects": [<absolute roots>]}`
plus optional `"unknown_members": true`; refused unless a regular file owned by the invoking
account with no group or other bits; a compare-then-rename replace through a 0600 temporary
with a parent-directory fsync) names the projects that connected a Codex home or Cursor config
root. Each installation also keeps a membership witness, `host_projects.witness_path_for(root)` =
`<state_dir()>/host-config-locks/<same key>.members` (same canonical JSON and checks as the record,
0600): every project it recorded for that root minus those it saw disconnect
(`write_connected_projects(..., departed=..., shared_removed=...)`); `recorded_members(root)`
reads it (absent or unreadable names none; maintained best effort after each record write and
deleted when the shared pieces go). The record write re-reads and compares the record with the
bytes the approved plan read, then publishes through an fsynced 0600 temporary and an atomic
rename with a parent-directory fsync; between the compare and the rename a writer that holds
neither lock (another installation) can still change it, so cross-installation updates are
narrowed, not excluded. `host_projects.host_config_lock(config_root)` is the per-root setup lock `apply_connection`
holds for every host across refresh, apply and the record update: an exclusive `flock` on
`host_projects.lock_path_for(config_root)` = `<state_dir()>/host-config-locks/<sha256 of the
resolved absolute path, NFC, case-folded>.lock`, a 0600 regular file owned by the invoking account
in a 0700 directory without symlinked components, opened `O_NOFOLLOW`, never deleted; it does not
serialise another installation's setups (the record's compare-then-rename narrows that race; it does not close it). A lock that cannot be
created, opened or taken raises `HostProjectsError("lock_unavailable")`, surfaced as the
`ConnectionError` reason `connection_lock_unavailable` before any change (the CLI `next_step`
names the lock folder). Verified members are the record's projects plus, for Codex, the project
the `[marketplaces.finishup]` binding names; only they are recorded, anchor the binding, or keep a
disconnect `detach`; `codex_marketplace.serving_projects(home)` (status `codex_home_projects`,
`shared_with`, `shared_removed_from`) lists those whose checkout still exists and serves the
manifest. A Codex project a byte-identical `[marketplaces.yoetz]` table names while its checkout
still serves the exact Yoetz-era marketplace document (`codex_marketplace._legacy_member`, ADR-048)
is a verified member too: Yoetz bound one project per home and registered the user-level server
every project uses without a record, so another project's connect records it, `connected_projects`
and `serving_projects` list it (serving its own legacy activation), `other_members` names it, and a
disconnect keeps the user-level registration for it; it never anchors the FinishUP binding or makes
a disconnect `detach` (it does not serve FinishUP's manifest), and it is not `unserved_members`. Possible users (Codex only), each a live checkout serving the exact manifest and a
marker-valid plugin source and never a verified member under any path spelling: the witness's
projects, always; and, while the record is missing with shared pieces present (including Yoetz-era
ones: a byte-identical `[marketplaces.yoetz]` or `[plugins."yoetz@yoetz"]` table, or a
FinishUP-shaped `[mcp_servers.yoetz]` entry) or marked `unknown_members`, `[projects."<path>"]`
rows with `trust_level = "trusted"`; the same Yoetz-era pieces found without a record make a
connect record `unknown_members` while such a possible user exists;
`codex_marketplace.possible_projects(home)` lists them,
`RemovalPreview.possible_users` carries them (bound into the removal digest with `unknown_after`),
status adds `codex_home_possible_projects` and `membership_unknown: true`, and the connect and
disconnect plan disclosure adds `membership_unknown: true` and `possible_users` (bound into
`preview_digest`; a connect excludes the connecting project), and a Codex `--remove-shared`
preview adds `shared_removed_from` (the other live verified members), as Claude Code and Cursor
do. They keep the shared pieces but
never anchor: a disconnect that would leave possible users and no verified member raises
`IntegrationReason.REMOVE_REFUSED` with `conflict: membership_unverified`, reported by the CLI as
reason `membership_unverified` with reconnect and `--remove-shared` continuations. Cursor
discloses `membership_unknown` and keeps the shared plugin while it is set (status reports it
before any record exists, reading whether shared pieces exist when it is asked); an owned Yoetz-era
`plugins/local/yoetz` counts as shared pieces present (`SharedProjectsStep(shared_present=...)`,
ADR-048), as it does for `integrate cursor plugin preview --action remove`; and its status adds
`connected_projects_observed`; Claude Code's own `plugin list` rows (one
`projectPath` per project-scope install) stand in for it. Plan changes add `detach_project`
(Codex), `uninstall_plugin` alone (Claude Code), and `record_connected_project|
forget_connected_project` (Cursor, record-only updates); the plan disclosure `shared_with` lists
the other projects that keep the shared pieces and is bound into `preview_digest`. Status adds
`codex_home_projects` and the project's own `activation_state` (Codex; `active` only for a
connected project) or `connected_projects` (Claude Code, Cursor). A connect through a
second path to an already connected directory fails as `project_connected_via_other_path`
(`IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH` for Codex, the same `ConnectionError`
reason for Claude Code and Cursor) with a `next_step` naming the connected path and the
disconnect that clears it; a malformed record is `connection_projects_record_invalid` (Cursor;
the Codex adapters raise `source_invalid` with `conflict: connected_projects`, and the CLI reports
`connection_projects_record_invalid` for Codex too on `setup run|status|disconnect`, probing the
record when a wrapper kept only `source_invalid`; Claude Code keeps no record), with a `next_step`
naming the file: make it owner-only again (`chmod 600`) or restore it; for Codex, if it must be
removed, connect every project again before disconnecting any (until then the witness and trusted
checkouts keep the shared pieces and a disconnect stops as `membership_unverified`); for Cursor,
removing it makes membership unknown. A plan that rewrites a shared FinishUP route on another
review mode while other projects use it (the Codex user-level registration, the Claude Code
shared source; Cursor's route is per project) reports `route_profile_before`,
`route_changes_for` (other serving members) and `route_changes_possible_for` (possible users):
digest-bound in `setup run --host` plans; in the TUI first-run plan
(`IntegrationPlan.mcp_reregister|route_profile_before|route_changes_for|
route_changes_possible_for`); in the historical Codex wizard report, which refuses a bare
`--accept` as `route_change_affects_other_projects`; in `integrate codex mcp preview`, whose
`preview_digest` then binds them (`canonical_digest({"mcp_preview_digest", "route_change"})`) and
whose `install` needs it (exit 2, `mcp_registration_route_change_affects_other_projects`); and in
`integrate claude plugin preview` (bound by its host-state digest over `installed_plugins.json`).
`route_profile_before` is read from the registration (`HarnessMcpService.observe`), never
inferred from a `reregister` action, which may change only the launcher or isolation root. When
membership cannot be read, the route change also carries `membership_unknown: true` (bound into
the same digests; the historical wizard and `install` refuse a bare `--accept`; the TUI and
`setup run --host codex` raise `source_invalid`). The `install` refusal names the exact
`integrate codex mcp preview --codex-path --codex-home --route-profile <requested>` command.
Without `--route-profile`, `run_host_connection(route=None)` (non-interactive `setup
run|status|disconnect --host`, and `setup status --next` outside `--operation review`) lets
`prepare_codex_connection` use the Codex home's registered FinishUP route (`strict` for a fresh home);
Claude Code and Cursor use `strict`.
`integrate codex mcp preview-remove|remove` reports `shared_with`, `possible_users` (plus
`membership_unknown: true` when membership cannot be read) and warning
`mcp_registration_shared_with_other_projects` and binds them the same way;
`integrate cursor plugin preview --action remove` reports `shared_with`, `membership_unknown`,
`shared_removed_for_every_project`. A Codex `setup disconnect` keeps the user-level registration
whenever the removal plan keeps the shared pieces (`RemovalPreview.keeps_shared`, also for
`already_absent`), `codex_marketplace.other_members(home, project)` (serving members, possible
users) is non-empty, a non-member's disconnect finds another live recorded project (serving the
manifest or not), or membership is unknown; also for an already detached or never-connected
project (`retained`, `shared_with` naming those projects, in the plan and the status, plus
`membership_unknown`; post-apply status `configured: false`, `shared_registration_retained:
true`). A disconnect that keeps the registration for other projects' own Codex configuration
(`admission_other_projects`, or a scan stopped at its bound of 32) reports the same post-apply
status: a project that is not connected reports `configured` only while its plan still removes the
registration. `other_members` returns `((), ())` only for a home that does not exist and raises
`IntegrationError` when membership cannot be read; callers treat that as unknown. A damaged
membership witness (`host_projects.recorded_members`) names no one rather than raising. When the
kept pieces serve the dangling binding's project whose directory is missing right now,
`RemovalPreview.missing_members` names it (bound into the digest) and the disclosure and status
add `members_missing`; with no live project among `shared_with`, an `unchanged` disconnect's
`next_step` also names the exact `setup disconnect ... --remove-shared` preview. The connect-path
`setup status --host codex` reports `enabled` and `configured` only for a connected project
(activation `active`), otherwise `shared_registration_retained: true` when a FinishUP registration
exists, and `membership_unknown: true` when membership cannot be read. The disconnect plan
disclosure adds `rebind_to` and, when the shared pieces go, `members_not_serving`
(`RemovalPreview.unserved_members`: live recorded projects, or a dangling anchor, that do not
serve the manifest). Only a recorded project may move or remove a dangling binding.
`members_not_serving` is disclosed also when the removal takes the shared plugin while the
user-level registration stays for other projects (a Yoetz-era bound project): the disclosure adds
`shared_plugin_removed: true`, `shared_with` names only the projects the registration stays for,
and the summary says the plugin is removed and only the registration stays (#1073).
After a completed or unchanged disconnect whose status keeps shared pieces for a missing
directory or with `membership_unknown`, `next_step` names the exact `setup disconnect ...
--remove-shared` preview (`cli.host_connection.kept_pieces_steps`, which the terminal interface
shows too).
`integrate codex plugin preview` reports `possible_users` (and `membership_unknown`),
`members_not_serving` and `keeps_shared`. CLI:
`finishup integrate <host> admission status|preview|grant|revoke --project-root`
(preview `--action grant|revoke`; Claude `--checkpoint`; the host roots the route observation
needs; `--accept --preview-digest` for the apply verbs, exit 3 without them, exit 1
`host_admission_<reason>` on refusal); raw path, OS, and parser exception text never crosses this
boundary.

`finishup provider status` emits the read-only `yoetz.provider-status/1` schema token. It reports two
non-substitutable verdicts. `semantic_ready` is repository-bound structural readiness:
service ready and unlocked, `verification.semantic` not `disabled`, an endpoint bound, the bound
provider's credential connected, the effective `llm_inference` channel enabled, and the trusted
current-session repository binding's `repository_grant_state == "granted"`. `endpoint` carries
`role: "primary"`; with a declared fallback (issue #582) the report adds `fallback_endpoint`
(`role: "fallback"`), `fallback_credential_connected` (`true|false|null`, read from the
service's `fallback_provider` capability), and a separate `fallback_provider_credential`
blocker (`not_connected` with its own next command, or `unknown`); the fallback is never an
input to `semantic_ready`, and a single-endpoint install omits the fallback fields entirely.
A Codex-subscription endpoint (primary or fallback) adds `review_budgets`. It is shaped
`{"routine"|"final": {"reasoning_effort", "output_limit", "effort_source"}}`, where
`effort_source` is `configured` or `legacy_single_effort`. `finishup provider codex-subscription
status` (`yoetz.codex-subscription-status/1`) carries the same object, plus
`codex_sandbox_unavailable` (`true` when Codex reported, through one of the two admitted
`configWarning`s, that its Linux sandbox cannot create user namespaces or that no system
bubblewrap is installed; ADR-006, 2026-10-14) and `codex_sandbox_unavailable_reason`
(`user_namespaces_unavailable|bubblewrap_missing|null`).
`repository_grant_state` and `repository_migration_state` expose the separate repository-authority
inputs without inventing another readiness verdict. `agent_route_semantic_ready` is
`semantic_ready` **and** one exclusive observed owner (`external|plugin`) with
`mcp_route.registered_profile == "policy"`. An unread, dual, foreign, or ambiguous route makes it
`false`; a policy-shaped file alone never creates readiness. The `mcp_route` object carries the
legacy external-registration fields `registration_state`, `registered_profile`, and
`configured_profile`, plus `observed`, `owner_source`, `ownership_state`,
`external_registration_state`, and `plugin_managed_state`. `owner_source` is
`external_registration|plugin_managed|dual|foreign|null`; `ownership_state` uses
`McpOwnershipState`. `observed: false` means exclusive ownership was not read unambiguously, not
that none is registered. `registered_profile: null` with `observed: true` means the observed state
has no single FinishUP route (`absent|dual|foreign`). For multiple discovered Codex executables, `binary_selection: consistent` reports agreeing
registration readings against one selected home. Read order prefers the configured Codex runtime
when discoverable, otherwise the newest reported version; `selected_codex_version` names its
version without a path. This does not attest the executable a host session launched. Disagreement
or a failed reading reports `binary_selection: inconsistent`, blocks agent readiness and admission
grants (refused as `host_admission_codex_binary_inconsistent`), and offers an explicit selector. If no executable can read the registration, selection is
`multiple`. `provider status` reports the closed `codex_binary_selection` blocker and a quoted
continuation retaining the invoking launcher, isolation root and inspected Codex home. Codex
admission commands accept `--codex-path` and `--codex-home` too; their path-free next commands
retain selector placeholders, and the caller must repeat the exact selected values. An explicitly unresolved
`--codex-path` uses the `not_found` state of that blocker. No arbitrary executable is chosen for a
readiness claim.
A strict registered route adds a `mcp_route_profile` blocker
with `scope: "agent_route"` and never moves `semantic_ready` or the exit code, because ADR-018
decision 2 makes the route ceiling process-local — CLI and terminal checks still dispatch. Route
observation is fail-soft by contract: no discovery failure, registration error, or unreadable entry
may raise or change the exit code.
The `mcp_route` object also carries `applied_profile` (the route the last accepted Codex MCP
install applied, from the owner-only state-root applied-route record; `null` when the record is
missing, corrupt, or unsafe) and `drift_since_install` (`true` only when the live observed
registration disagrees with that record; unread observations never report drift). Later installs
overwrite the record — including an accepted install that had nothing to write — and `mcp remove`
clears it, so absence with no record reads as no drift. A strict ceiling check served while the
applied record says `policy` keeps the same
`blocked_by_policy` / `route_semantic_ceiling` status, reason, and null provenance, and carries
the `optional_semantic_review_registration_drift` coverage gap alongside the ceiling gap only when
the serving command declares `--host codex`; generic, Claude, and Cursor processes cannot be
attributed to the Codex record. Its
receipt names the recovery (re-run `mcp preview` / `mcp install --route-profile policy`, start
a fresh Codex process) as a conditional, because a strict route reached outside the ceremony is
a legitimate owner action. A ceiling with no applied-policy record keeps the terminal wording. The
bridge emits `registration_drift` at startup only for an explicit Codex serving identity; generic
legacy invocations remain unknown and keep the strict ceiling without a Codex drift claim.
MCP `status view=versions` and the `mcp serve` descriptor intentionally stay serving-only: they
name the live route of the serving process, and the applied-vs-serving drift join lives in the
CLI status surfaces — so the omission there reads as decided, not missing. The closed
`registration_drift` hook diagnostic has exactly one emitter, the MCP bridge at startup, under
the `mcp_serve` event: it is the only process that can compare its serving route against the
record without a host subprocess the hook budget cannot afford.
The report also carries `host_admission` (issue #467): one object per host (`claude|codex|cursor`)
with `state` exactly `absent|present|partial|foreign|unknown`, `observed`, and per-surface
`entries` (`surface`, `state`, `entry`, closed `detail` token, `file_digest`), read from the hosts'
own project-scoped files (`.claude/settings.local.json`, `.codex/config.toml`,
`.cursor/permissions.json` + `.cursor/cli.json`) under the repository root resolved from the
workspace locator: the locator is absolutized without resolving its final symlink, then walked up
to the nearest `.git` entry, so a subdirectory launch reports the root's files rather than
`absent`, and a symlinked root still reads `unknown`. `unknown` means the
host file could not be read, never that no admission exists. A `present|partial` admission whose
grant is known not to permit external review, or (Codex) whose observed registered route is
`strict`, adds a `host_admission_drift` blocker with `scope: "agent_route"` and `host`; it never
moves `semantic_ready` or the exit code, and the report never removes anything.

An unbound repository session reports `repository_grant_state=null` and `semantic_ready=false`
rather than treating the machine ceiling as authority. Provider status remains structural readiness
evidence, not installed-wheel proof of dispatch or receipts.

When a Codex subscription runtime is bound (issue #855), the report adds `external_runtime`:
`role` (`primary|fallback`), the closed structural `state` from the ADR-006 retention amendment
(`ready` or one refusal token), the independent `capability`, `executable`, and `home` axes,
`uses_managed_runtime` (`true` when the binding points at FinishUP's retained runtime copy, `null`
when unknowable), and `next_command`. It is computed locally from the binding, executable bytes,
and dedicated home; it starts no Codex process and checks no sign-in. A non-`ready` state adds an
`external_runtime_structure` blocker with `state`, `role`, and the exact continuation. The
credential blockers for that runtime name the same continuation instead of the status probe. A
non-`ready` primary runtime makes `semantic_ready` false even while a service composed earlier
still reports the credential connected. A `ready` binding on a host installation keeps
`next_command: "finishup provider codex-subscription repair"` as advice, with no blocker.
`next_commands` lists each continuation once.

The evaluator is admitted by capability, not by one pinned build (ADR-006 capability amendment,
2026-10-13): any stable Codex release at or above `0.157.1` whose retained bytes pass the check
(profile `codex-evaluator/capability/v2`). A passed check commits
`yoetz.codex-evaluator-capability/1` (`capability.json`) beside the retained runtime:
`capability_profile`, `runtime_floor`, `runtime_version`, `source_identity`,
`platform` (`os`, `architecture`), `executable_sha256`, `code_mode_host_sha256`,
`app_server_schema_sha256` (digest of the checked protocol-subset facts),
`isolated_config_sha256`, and `checks`. The binding's `capability_cell_sha256` is that record's
canonical digest. The configuration and `runtime_evidence` field sets are unchanged. The closed
structural states add `codex_runtime_version_unsupported` (continuation `repair`), and a
pinned-cell binding reports `codex_runtime_profile_outdated`.

`finishup provider codex-subscription runtime status --json` emits
`yoetz.codex-evaluator-runtime-status/2`. It carries:
- `platform` (`darwin-arm64|linux-x64` or `null`), `runtime_floor`, `capability_profile`, and
  `store` (`present|absent|unsafe`);
- `retained_runtimes`: one entry per retained release, newest first, with `source_identity`,
  `runtime_version`, `path`, `state` exactly
  `absent|verified|incomplete|unchecked|changed|invalid|unsafe`, `code_mode_host_path`, and the
  recorded `executable_sha256`, `code_mode_host_sha256` and `capability_profile`, each `null`
  without a record;
- `binding`: the same axes plus `executable_path`, `uses_managed_runtime`, `capability_profile`,
  `runtime_version`, `codex_home` and `endpoint_role`;
- `login_checked: false` and `next_command`.

It exits `0` when no binding exists or the binding is `ready`, otherwise `20`.
`repair` emits the subscription status shape plus `state_before`, `source`,
`runtime_retained_from`, `runtimes_passed_over` (closed tokens of newer candidates that failed the
check or lack the model), `changed_fields`, `login_reused`, `endpoint_role` and `config_path`.
`setup` adds the same `runtime_source`, `runtime_retained_from` and `runtimes_passed_over`.

`yoetz.codex-subscription-repair-plan/2` replaces `changed_fields` with `runtime_version_before`,
`runtime_version_after` and `candidates` (`source`, `path`, `runtime_version`, newest first),
because identity fields are known only after the check. `yoetz.codex-subscription-preview/2` adds
`runtime_floor`, `capability_profile` and `capability_check`, and drops `app_server_schema_sha256`
and `capability_cell_sha256`.

`runtime install` (`yoetz.codex-evaluator-runtime-install/2`) retains and checks one release and
reports its `capability_cell_sha256` and `capability_profile`. `runtime remove`
(`yoetz.codex-evaluator-runtime-remove/2`) deletes every retained release the binding does not use
and reports `removed_runtimes` and `kept_runtime_path`; it is refused with
`codex_evaluator_runtime_in_use` when only the bound release remains. Both report
`binding_changed: false` and `host_installation_changed: false`; neither edits the binding.

Every `integration_preview` preview/status body and every `integration_execute` body carries an
explicit required `harness` discriminator. Its frozen v0.1 schema value is exactly `codex`; omission,
defaulting, environment inference, and unknown values fail at control-schema admission before an
`IntegrationRequest` or `IntegrationStatusRequest` is constructed.
`IntegrationDiagnosticSink.record_integration(IntegrationDiagnostic)` is separate from startup
`DiagnosticsPort.record(StartupCheckResult)`. Its frozen diagnostic contains only harness, action,
phase/outcome, before/after state, compatibility, managed-file count, structural digests, and an
optional closed integration reason; it has no project path, content, environment, Git, task, or
exception field.

### Portable plugin carrier and host activation (ADR-023; artifact/MCP slices implemented by #150/#151)

The names below were registered by ADR-023; the artifact and optional plugin-managed MCP slices are
implemented in `ports/plugin_artifacts.py` and `adapters/integrations/portable_plugin.py`. Later
child issues of #148 own activation and per-host evidence cells. A portable plugin is a
carrier, never an authority: it may carry metadata, shared skill bytes, and an optional exact MCP
declaration, and it cannot authorize disclosure, hold credentials, unlock the vault, approve
observation, call providers, strengthen coverage, or replace a receipt (ADR-008, ADR-023).

`PortablePluginPlan` is the one canonical neutral plan every manifest/configuration is generated
from: common metadata (name exactly `finishup`, version, description); canonical skill/resource byte
sources (the packaged `guidance/` mirrors, byte-identical per ADR-010); `format_profile:
PluginFormatProfile`; `mcp_ownership: McpOwnership` with `mcp_route_profile` (`policy|strict`)
present exactly when plugin-managed; an optional host-extension profile; schema and renderer
versions (Agent Plugins spec pin `1.0.0` plus the plan renderer version); and the complete
managed-file inventory with relative paths, sizes, and SHA-256 digests. Agent Plugin JSON is never
the input for another host's manifest; projections share only the plan (ADR-023).

- `PluginFormatProfile` is a closed enum; membership is exactly
  `agent_plugins_1|claude_code_plugin_native|codex_plugin_native|cursor_plugin_native`. A new member requires a reviewed projection design and
  ADR-023-conformant root registration before any render targets it.
- `McpOwnership` is exactly `external_registration|plugin_managed`. `McpOwnershipState` is the
  closed observed-owner state `absent|external|plugin|dual|foreign|ambiguous`; `dual`, `foreign`,
  and `ambiguous` are explicit reported states, never silently resolved or overwritten (ADR-018,
  ADR-023). Child-issue shorthand does not add members: `owned` resolves to `external|plugin` from
  the observed source, and `foreign_present` projects to `foreign`.
- `HostSurface` is the closed host-product enum
  `codex_cli|chatgpt_desktop|cursor_ide|cursor_cli|cursor_sdk_local|cursor_cloud|claude_code`, used only to key
  evidence cells. It is distinct from `HarnessId` (`claude|codex|cursor`); format
  compatibility earns no `HostSurface` support claim, first-party identity, or coverage (ADR-005,
  ADR-023). A Cursor surface consuming the portable artifact is a *portable* cell; one consuming a
  generated native projection is a *native* cell; Claude Code is a *native dual-target* host whose
  project-scope and user-scope targets are separate cells.
- `PluginOperationState` is the closed mutation status
  `not_started|in_progress|completed|refused|outcome_unknown`. Every mutating artifact/activation
  request carries an exact request identity; same-request replay returns the stored result or
  reconciles through status; timeout or connection loss reports `outcome_unknown` and never implies
  failure; retry cannot create a second stage/apply/remove; status carries no user-controlled
  structural content (ADR-023).
- `PluginProofFacet` is the closed independent-facet list `source`, `rendered_artifact`,
  `installed_bytes`, `host_discovery`, `host_activation`, `skill_delivery`, `mcp_owner`,
  `mcp_binding`, `mcp_runtime`, `model_use`, `trigger_capability`, `observation_consent`,
  `observation_evidence`, `service_readiness`, `semantic_readiness`, `provider_dispatch`,
  `privacy_receipt`, `workflow_receipt`. No facet implies another, and format validation proves
  none of activation, observation, AI-powered review dispatch, or closure (ADR-023).

`PluginArtifactPort` methods are `preview_artifact`, `install_artifact`, `status_artifact`, and
`remove_artifact`; interrupted-swap recovery is expressed through `status_artifact` reconciliation,
never automatic repair. `HostActivationPort` methods are `observe_discovery`,
`observe_activation`, and — only when authorized — `preview_activation`, `apply_activation`,
`preview_removal`, and `apply_removal`.
Both are siblings of `IntegrationsPort`, `HarnessMcpPort`, and `ObservationPort` under the
ADR-010/ADR-012 sibling-port rule: a host adapter may compose them but cannot collapse their state
or authority, and no port's status field implies another's. Mutations preserve the full safe
artifact lifecycle (exact before/after preview and accepted digest, stale-preview rejection,
safe-root containment, no symlink members, complete digest inventory, no unmanaged/modified
overwrite, failure-atomic replacement, installed-byte verification, no
filesystem-presence-to-activation inference). The #150 standalone artifact install/remove path
consumes the ADR-016 `review_only` single-shot trusted review. Codex marketplace activation and
removal use the ADR-012 digest-bound `--accept` composition already used by MCP
preview/install/remove; they do not consume `plugin_artifact_apply`, which remains the macOS
Cursor portable-artifact presence cell and would fail closed on this host (issue #419). Cursor
standalone activation apply remains owned by a later child and unavailable without the #409
presence cell. The ADR-012 setup composition remains its own separately authorized path
(ADR-023 decision 11).
Codex `preview_removal` / `apply_removal` refuse foreign, modified, dual, or otherwise
conflicting marketplace, config, inventory, or cache surfaces with `remove_refused` and a closed
`conflict` token (`personal_marketplace|repository_marketplace|config_marketplace|config_plugin|
inventory|cache|membership_unverified`). `RemovalOutcome` is `remove|already_absent|detach`:
`detach` (#1058) means other connected projects that still serve the exact FinishUP manifest keep the
home's binding, enable table, cache and MCP registration; the preview names them in `shared_with`
and, when the binding named this project or names a project that is deleted or lost its manifest,
the project it moves to in `rebind_to`; apply rebinds first, then removes the project's canonical
`marketplace.json`, then updates the connected-projects record. A detach also deactivates the
project's own Yoetz-era activation (ADR-048): its exact legacy tables leave in the same config
write, then its exact legacy `marketplace.json` and marker-validated legacy cache go
(`legacy_removed_block`, `legacy_cache_versions`, `legacy_marketplace_json_planned`; the preview
digest binds both the multi-project facts and the legacy suffix), and the result must read
`legacy_activation: false`. With no verified member left, a
binding to a deleted or manifest-less project is removed with the shared pieces: its exact
tables and managed cache trees are removed directly (no `codex plugin` command, which fails
through such a binding), also under `--remove-shared`. The
activation side treats a binding to another such project as the shared marketplace
(`_plugin_inventory` expects that anchor's source), counts a project as activated only when it is
the anchor or in the record, moves a binding whose project lost its manifest to the connecting
project, and refuses an alias of the same directory as `project_connected_via_other_path`.
Cache purge is default-off. The removal digest binds the exact trusted project
root as well as the selected executable, Codex home, configuration/cache preimages, planned host
commands, and cache-purge choice. Cache preview and apply share descriptor-relative no-follow
total-entry, recursion-depth, relative-path, file-count, per-member, and aggregate-byte bounds.
Apply retains the validated version descriptor through quarantine rename, binds deletion to the
exact approved member names and bytes, refuses
observable additions/changes before unlink, restores the exact version name when drift occurs
before the first unlink, preserves the remainder after deletion starts, and never sweeps an
unapproved name into deletion.
Repository `marketplace.json` and any host-created empty `config.toml` cleanup use the same
descriptor/inode/byte-bound private-quarantine rule rather than pathname-only unlink. The
repository walk is anchored on the project root, which is judged by the shared project-root rule
exactly as install judged it (ADR-007, 2026-10-14); a Codex-home anchor and every descendant stay
the running user's own.
Pre-mutation drift is `preview_stale`; once any accepted host/config/filesystem mutation has
started, including a zero-exit mutating host command whose JSON result is malformed, a later
conflict is `write_failed` because partial state is possible. A successful
cache-only deletion sets the same operation-wide fence before final inventory/config/activation/
skill verification. The adapter does not
claim an atomic compare-and-unlink primitive for a non-cooperating same-UID writer's final POSIX
content window, so the operator must quiesce such writers. After a successful removal,
`codex plugin list
--marketplace finishup --json` is empty and `config.toml` has no finishup tables;
`inspect_activation` / observe status reports `installed_not_activated` when the managed plugin
source at `.agents/plugins/finishup` remains (issues #387 and #347), including a modified or
untrusted copy, and `not_installed` only when that source is also absent. A second removal is `already_absent`. The skill tree, consent records, and
observation store are intentionally left in place.

The implemented artifact operation is exactly `plugin_artifact_apply`. Its prepare target is the
portable preview digest, which already binds target identity, current-state digest, action,
format/schema/renderer versions, intended and current MCP ownership, optional route profile, exact
route bytes through the artifact inventory/digest, the exact rollback digest when present, and the
complete sorted future inventory.
It is `review_only`, never agent-chat-authorizable, and its one pending review is consumed before
one install/replace/remove attempt. Same-request replay returns the stored process result; after
restart or an ambiguous filesystem outcome the caller must reconcile through `status_artifact`,
which never performs automatic repair. The portable marker schema is
`yoetz.portable-plugin-install/1`; the pre-existing native marker remains
`yoetz.codex-plugin-install/1`, enabling exact whole-directory migration and rollback without a
pathname merge.

The #150 artifact wire-neutral domain shapes are closed:

- `PluginArtifactAction` is `install|replace|remove|noop`; callers cannot request `noop`.
- `PluginArtifactState` is
  `absent|portable_exact|portable_managed|native_managed|modified|partial|unmanaged|unsafe|recovery_required`.
  Only exact marker-verified managed states are mutation candidates; `recovery_required` is a
  preserve-and-reconcile state, never an automatic-repair instruction.
- `ArtifactTarget` contains one redacted trusted-project root. `ArtifactAuthority` is exactly one
  of `setup_composition` or `review_only`, plus the exact preview digest; the review-only branch
  also carries the one-use pending review ID. The string discriminator is not itself authority:
  the adapter consumes the corresponding injected authority port, and the default adapter denies
  both channels.
- `PluginArtifactPreview` carries request ID, action, state before, current `McpOwnershipState`, target-identity digest,
  current-state digest, artifact digest, the exact canonical-native rollback digest when migration
  would preserve or removal would restore one, preview digest, the complete `PortablePluginPlan`,
  and sorted structural warnings. The preview digest binds the rollback digest, so the consumed
  authority target binds those exact bytes; a missing or changed rollback is stale and refuses
  before mutation. Apply revalidates the bound preview after authority consumption and before its
  first filesystem mutation. It carries no raw target path or member contents.
  For plugin-managed mode that owner state must be composed from plugin and external/global
  observations by the caller; the neutral artifact adapter cannot infer the latter from tree
  absence, so its uncomposed default is `ambiguous` and refuses preview.
- `PluginArtifactStatus` carries artifact and installed-byte state, `PluginOperationState`, detected
  format, artifact/installed digests, desired and observed MCP ownership, exact plugin-managed route
  profile, marker validity, rollback
  availability, and one independent status for every `PluginProofFacet`. Unobserved facets remain
  `not_observed`; installed bytes never imply discovery or activation.
- `PluginArtifactResult` carries request/action/operation state, before/after artifact states,
  preview/artifact/installed digests, and sorted changed member names. The bounded refusal reasons
  are `authority_required|destination_conflict|format_unsupported|human_authority_unavailable|manifest_invalid|mcp_ownership_conflict|modified_copy|operation_conflict|preview_stale|recovery_required|remove_refused|request_identity_conflict|source_invalid|target_unsafe|target_untrusted|write_failed`.

The `yoetz.portable-plugin-install/1` marker contains only schema, format profile, FinishUP/schema/
renderer versions, exact MCP ownership and optional route profile, artifact digest, complete sorted managed-file rows
(`relative_path`, `size`, `sha256`), and its canonical marker digest. It contains no project path,
user value, timestamp, credential, secret reference, transcript, host-activation claim, or receipt.
The native rollback candidate must additionally byte-match the current canonical
`render_plugin_install_tree(codex_version=None)` projection, including its native marker's adapter,
harness, scope, and FinishUP version identity. A marker-consistent prior or fabricated native tree is
not a rollback candidate and remains preserved as `modified` or `recovery_required`.

### Cursor local harness contract (issue #153)

`discover_cursor_ide` reads installation identity without proving activation or a native-session
capability cell. The macOS path uses bundle metadata and the main executable digest. The Linux
path accepts an explicit package root or native executable, resolves the selected path, reads
`resources/app/package.json` version and `resources/app/product.json` commit/application name,
and hashes the executable after reading its ELF64 little-endian ET_EXEC/ET_DYN signature and
x86-64/aarch64 architecture. Version and commit metadata are bounded printable ASCII identity
fields.
Internal package symlinks are
refused; metadata reads are bounded to 1 MiB each. Missing roots/executables are unavailable,
unrecognized layouts are `cursor_ide_layout_unsupported`, and malformed or foreign identities
are `cursor_ide_identity_invalid`. Inspection never executes the package or extends profile
`evidence_case_ids`. A Linux identity inside WSL supplies no Windows-side IDE or Remote WSL
session evidence (issue #722). The helper currently has no CLI, MCP, TUI, or receipt caller;
library callers and unit tests are its only entry points until a separate integration wires it
into setup or discovery.

`HarnessId` membership is now `claude|codex|cursor`. Adding Cursor changed no method on `IntegrationsPort`,
`PluginArtifactPort`, `HarnessMcpPort`, `ObservationPort`, or the six workflow operations.
`PluginFormatProfile` membership adds `cursor_plugin_native`; `HostSurface` adds
`cursor_sdk_local` beside the existing `cursor_ide|cursor_cli|cursor_cloud`. Cursor Cloud remains an
unpopulated evidence cell.

`CursorPluginTarget` is an explicit absolute Cursor configuration root plus scope exactly `user`.
It is redacted in representations and never inferred from regular Cursor, `$HOME`, caches, or a
single installed candidate. The managed destination is `plugins/local/finishup` below that selected
root. `CursorPluginArtifact` contains one `PortablePluginPlan`, one sorted member mapping, and one
artifact digest. Native artifacts also carry the validated `FINISHUP_ISOLATED_ROOT` binding when the
invoking runtime is isolated; portable artifacts never carry a host isolation binding. Its format
is exactly `agent_plugins_1` or `cursor_plugin_native`; one artifact never contains both root
`plugin.json` and `.cursor-plugin/plugin.json`. The host may still consult the regular shared
`~/.cursor/plugins/local/finishup` during discovery when launched with another user-data directory;
an isolated Cursor home does not prove isolated plugin discovery. The explicit target, child root
binding, and host discovery observation remain separate proof facets.

`CursorPluginPreview` carries request ID, effective action, before state, exact format, target
identity digest, current-state digest, artifact digest, preview digest, intended MCP ownership,
observed `McpOwnershipState`, optional exact route, proposed isolated root or null, and sorted
warnings. `CursorPluginStatus` carries artifact/operation state, detected format,
artifact/installed digests, marker validity, rollback availability, one `CursorMcpObservation`,
one `CursorMcpRuntimeObservation`, one `CursorLauncherStatus`, the Cursor-specific isolation
binding (`ambient|isolated_exact|missing|different|unobserved`), and every independent
`PluginProofFacet`. `ambient` and `isolated_exact` require both a marker root match and intact
root-bearing MCP/hook members; a marker alone never proves that the child launch binding remains
intact. `different` covers a changed root or a root-bearing member whose binding no longer matches.
`CursorPluginResult` carries request/action/operation, before/after states, format,
preview/artifact/installed digests, and sorted changed members. Portable artifacts retain marker
schema `yoetz.cursor-plugin-install/1`. Newly rendered native artifacts use
`yoetz.cursor-plugin-install/3`, which adds the resolved absolute invoking `finishup` executable path
(never a different ambient-PATH installation when the CLI was invoked by an explicit absolute or
relative path) to the
format, renderer/FinishUP versions, hook mapping version, MCP owner/route, exact isolated-root
binding (or null for ambient mode), artifact digest, exact managed inventory, and marker digest.
A valid legacy native `/1` or `/2` marker remains managed but reports `modified` against the
current desired artifact when its binding is absent, so an exact previewed replace or remove
remains reachable. Neither schema carries a project path, content, credential, transcript,
timestamp, activation, coverage, or receipt claim.

Native hooks **and the plugin-owned `mcp.json`** launch that one recorded launcher (issue #468):
the MCP entry is `command = launcher[0]`, `args = [*launcher[1:], "mcp", "serve", "--host",
"cursor"(, "--semantic", "off")]`, never a bare `finishup` that Cursor's sanitized desktop PATH may
resolve to another installation. In isolated mode the entry carries exactly
`env = {"FINISHUP_ISOLATED_ROOT": "<validated-root>", "YOETZ_ISOLATED_ROOT": "<validated-root>"}`
(both names, one value; ADR-048) and every native hook command carries the same shell-safe
assignments; ambient artifacts omit both. Readers accept either name alone or both equal. Because these entries are managed
members, their bytes are part of the artifact digest and marker inventory. Route-shape recognition
accepts a hand-written bare `finishup` or one of the known launchers — this artifact's and the
installed marker's — followed by the exact serve arguments, optionally with that one structurally
valid environment binding. Lifecycle ownership passes the artifact's exact expected root into the
same classifier; a different valid root is therefore `foreign` and cannot count as owned or
admitted. Any other command, prefix, or key set is `foreign`. `CursorLauncherStatus` reports
`artifact_launcher`, `installed_launcher`,
`executable` (`matched|drifted|missing|unbound|unobserved`: the installed launcher versus the one
this runtime would render, and whether it still exists), `mcp_binding`
(`exact_launcher|ambient_path|absent|foreign|unobserved`: what the installed plugin entry spawns),
and `identity`, a `LauncherIdentity` probed by running the installed launcher's read-only `version
--json` through `finishup.adapters.integrations.launcher_probe` and comparing package version,
`control-result` schema version, and resource-manifest digest with the status-reading runtime
(`observed=false` when the probe cannot answer; nothing is inferred). The runtime observation adds
`executable_activation` (`unobserved|matched|unproven|executable_mismatch`): the tokens before
`mcp serve` in a live Cursor-helper child are compared with the installed launcher without
retaining argv, and a child on a different explicit executable forces
`activation=full_restart_required`. Carrier-byte equality therefore proves what the host spawns;
the identity probe and live executable match are the separate runtime facts.

Cursor lifecycle is exact-preview bound and whole-directory atomic. Install, replace, and remove
consume the ADR-016 `review_only` single-shot trusted review of `plugin_artifact_apply` prepared
for that exact preview digest, exactly as the portable artifact path does. `--accept` is operator
acceptance of a digest, never authority: the CLI passes the pending-bound `ArtifactAuthority` to
the adapter, which refuses with `authority_required` when none is presented. In the pinned macOS
Cursor cell, `MacOSArtifactUserPresence` invokes the SIP-protected `/usr/bin/osascript` with a
fixed JavaScript-for-Automation LocalAuthentication program, a minimal environment, no shell, and
a fresh `deviceOwnerAuthentication` context with authentication reuse disabled. The OS prompt
names `plugin_artifact_apply`, the full preview digest, and pending review ID. Only the exact
stdout token `approved` may release the pending for atomic consumption; cancellation, unavailable
policy, timeout, malformed output, nonzero exit, non-macOS hosts, or binding mismatch becomes
`human_authority_unavailable` before mutation. This scoped adapter is not the service-wide
`UserPresencePort` and grants no authority for vault, credential, privacy, setup, or another
plugin operation.

The cell is selected per platform by `select_artifact_user_presence`
(`adapters/integrations/artifact_presence.py`), shared by the Cursor and Claude Code lifecycles,
and every host `preview` reports the selection as `authorization.human_presence` with `mechanism`
(`macos_local_authentication`, `linux_pam_trusted_console`, or `unsupported`), `platform`
(`sys.platform`), `ingress` (`os_dialog`, `trusted_console`, or null), and `supported`, next to
the unchanged `requires_os_authenticated_prompt`. On Linux, including a distribution under WSL 2,
`LinuxArtifactUserPresence` (`linux_artifact_presence.py`) writes a banner naming
`plugin_artifact_apply`, the full preview digest, and the pending review ID to the ADR-008
trusted foreground console, reads the invoking account's operating-system password there once
with echo disabled, and verifies it through Linux-PAM (`libpam.so.0`, fixed service `login`,
`PAM_DISALLOW_NULL_AUTHTOK`) followed by `pam_acct_mgmt`; an unprivileged process can only ever
verify its own account through `unix_chkpwd`. The console is ingress, never authority. Exactly
one hidden prompt is answered; an echoed, repeated, or unknown prompt, cancellation, EOF, an
empty or wrong password, a locked or expired account, a missing PAM stack, no verified console
(an agent's pipe, redirected stdio, or a background process group), or the 130-second deadline
becomes `human_authority_unavailable` before the pending is claimed, and operating-system prompt
or error text is never reflected. An unsupported platform fails closed with the same reason.
Neither cell is the service-wide `UserPresencePort`.

Linux PAM deadline implementation (issue #719): the trusted console process retains password
input and terminal restoration, while a disposable Python worker performs the native PAM calls.
The bounded password travels through an anonymous pipe only. The parent kills and reaps its
worker on timeout or cancellation; a blocked PAM module cannot defer the parent deadline.
No PAM prompt or error output is forwarded. Empty, overlong, and NUL-containing passwords are
refused before launching the worker.

Install and remove replays are idempotent at the selected state: a committed operation whose
result was lost reconciles instead of refusing, touching no bytes and consuming no second review.
Replace is deliberately not reconciled — the accepted digest bound the pre-commit tree, which the
replacement destroyed, so a replace replay after commit reports `preview_stale` and the caller
reconciles through `status`. Install reconciles when the destination is marker-valid at the
accepted format and artifact digest and the accepted preview digest equals a digest an `absent`
preview would produce for that artifact and target at an admitted MCP ownership state; remove
reconciles at `absent`, whose pre-commit tree digest no longer exists to re-prove. Neither
recognition is request-bound: the preview digest is a pure function of its inputs, so a caller may
recompute one for a request that committed nothing and obtain the same answer. Both branches are
read-only equivalents of `status` — no mutation, no authority consumed, no state claimed that is
not on disk — so that reachability is admitted rather than load-bearing. Every other state still
refuses. Install or replace refuses modified, unmanaged, symlinked, dual,
foreign, ambiguous, stale-preview, or recovery-required state without overwrite or automatic
repair. Remove accepts only marker-valid managed bytes; an independently present MCP source does
not block removal because the operation preserves that source. Removal also preserves ledgers,
vault/keyring/provider/privacy state, unrelated settings, and Cursor caches.

`CursorMcpSource` is exactly
`inline_send|inline_create|plugin|project|user`. `CursorMcpObservation` carries observed
`McpOwnershipState`, winning source or null, exact route or null, ordered present sources, and an
observation boolean. `CursorPluginStatus` also carries one `CursorMcpRuntimeObservation`: whether a
live process scan ran, exact bounded counts of classified policy/strict/foreign `finishup mcp serve` processes,
the live helper route or null, and `activation` exactly
`unobserved|matched|full_restart_required`. Classification requires an exact `finishup` launcher token
and known serve suffix; an unavailable or truncated scan is `unobserved`. Counts and closed tokens only — never raw argv, paths,
or parent command lines. File registration is not live runtime: a plugin-managed `policy` tree with
a surviving Cursor-helper child on the strict argv is `full_restart_required`, and `HOST_ACTIVATION`
stays `not_observed`. Reload Window is not a sufficient activation proof. SDK precedence is exactly that enum order. A higher-precedence or duplicate
same-name source cannot create a plugin-managed pass: plugin plus external is `dual`, multiple
same-class sources are `ambiguous`, and any non-exact same-name entry is `foreign`. Route
recognition is key-set exact — exactly `command`, `type`, `args`, or those three plus the one
`env` binding above; arbitrary additional keys such as `cwd` remain foreign.

`CursorProjectMcpTarget` names an explicit absolute project root and Cursor configuration root.
The POSIX project-registration adapter exposes preview, status, apply, and removal through
`integrate cursor project-mcp`; its only owned file entry is project `.cursor/mcp.json` key
`mcpServers.finishup` with the exact invoking launcher, native Cursor serve suffix, and isolated-root
binding. It refuses any same-name user or plugin source, duplicate source, or foreign project
entry. Status, preview and apply judge the project root by the shared project-root rule
(ADR-007, 2026-10-14) and keep the Cursor configuration root and project `.cursor` the running
user's own. A preview binds target directory identities, all three configuration preimages, route,
launcher, and replacement digest. Apply rereads the inputs, atomically replaces through a pinned
directory, and verifies the resulting configuration before reporting success. Host writers do
not participate in compare-and-swap, so that limitation remains explicit. Status proves only
configuration ownership; host trust remains unknown and runtime binding unobserved. This route
lets Cursor supply native project roots without widening the bridge's workspace authority.
Removal and strict registration compose the existing project admission reverse sweep.

`CursorSdkBinding` is exactly `typescript|python`. `CursorArtifactIdentity` carries binding,
package version/digest, bridge protocol exactly `sdk.v1`, and optional bridge digest.
`CursorSdkProfile` carries that identity, explicit unique `plugins|project|user` setting sources,
the frozen precedence tuple, MCP ownership, sandbox boolean, and approval mode
`default|allowlist|full`. Plugin-managed requires `plugins`; external registration requires
`project` or `user`. Inline sources are never ambiently accepted as ownership evidence.

The 2.1.0 control-request wire admits `cursor_version`, `model_id`, and `model_effort` in
`observation_envelope.structural_payload` beside `codex_version`, on the same bounded 1..128 token
alphabet the domain enforces for them. `structural_payload` is closed, so those three keys are
what makes a Cursor observation deliverable rather than a lenient default.

`ObservationSource` adds `cursor_hook`. The pinned native profile advertises only
`sessionStart|sessionEnd|afterMCPExecution|afterFileEdit|stop`; `afterAgentThought` is excluded.
`CURSOR_HARNESS_PROFILE.hooks_by_capability_profile` binds that nonempty profile only to
`cursor-ide-3.17.8`. The portable CLI cell is exactly `None`: Agent Plugins do not carry hooks.
SDK profile ids and versions are absent from the supported harness profile; their retained
metadata fixtures are marked `metadata_only` and `not_a_support_claim`. The SDKs' file-based hook
loading has no independent installed-artifact, event-delivery, privacy-filtering, failure-behavior,
or accepted-observation proof. Native IDE rendering or schema validity cannot populate those
neighboring cells.
Cursor ingress maps only bounded session/generation/tool IDs, exact Cursor/model/effort tokens,
duration, capability profile, and an installation-keyed HMAC changed-path commitment. Cursor's
`afterMCPExecution` duration is admitted as a finite decimal millisecond value only at this host
boundary and truncated to the canonical integer `duration_ms`; the canonical parser remains
float-free. Discarded vendor-field floats are replaced transiently, and malformed or unsafe Cursor
envelopes remain fail-open while recording the payload-free `cursor_payload_invalid` diagnostic; a
body over the shared 1 MiB hook ingress cap is separated from that vendor-shape refusal. A
complete body that also fits the 8 MiB skim cap is admitted whole when dropping its image bytes
brings it under the ingress cap; otherwise it is admitted as a structural row with
`payload_content_omitted` and `cursor_payload_content_omitted` (no gap for a scoped FinishUP tool
spelling; the generic `MCP:<tool>` spelling names no server and keeps the gap). A larger body, or a complete
oversized body that fails validation, records `cursor_payload_too_large` with the
`payload_too_large` coverage gap and no structural row.
The `model` spelling from execution/file-edit events normalizes to `model_id`; a valid `model_id`
spelling wins when both are present. It discards
prompt, reasoning, response text, paths, file contents/edits, MCP/tool inputs/results, transcripts,
commands/output, and email before storage and never reconciles a Cursor transcript stream. It uses
`workspace_roots` transiently, then `CURSOR_PROJECT_DIR`, then the explicit hook argument to choose
one locator. Multi-root input must contain the project directory; the nearest safe `.git` file or
directory normalizes subdirectories and worktrees without spawning Git. Root/home locators,
symlinked ancestors, unsafe markers, oversized/control-bearing values, and ambiguous multiroot
input fail closed. Plain roots never enter structural state, diagnostics, errors, or stdout.
Unresolvable and resolved-but-unconsented inputs record distinct payload-free diagnostics. Hooks
are fail-open and advisory; configuration/trigger-only state earns no observation coverage.
The selected locator retains its exact filesystem-encoded spelling through lookup and commitment;
Unicode normalization never aliases distinct directories. A grant created under a differently
normalized spelling does not authorize its sibling and requires an explicit regrant.

The default desktop Cursor MCP bridge has an additional session binding: on the first workflow call it asks
the MCP client for the standard `roots/list` result. The Cursor-specific adapter accepts local file
URIs and the strict absolute local path shape emitted by the reviewed host, then safely canonicalizes
every root. Without a validated project selector, the roots must canonicalize to one repository.
An owned project registration renders the exact absolute `--project-root` and binds that startup
selector to the exact project entry, launcher, route, and directory/configuration identity. The
selected repository must occur in the active client's validated root inventory. Registration
identity is revalidated before each workflow call; a changed registration retires the bridge.
The selector resolves a multi-repository inventory but cannot substitute for missing host roots.
Process CWD, hook payloads, and public workflow `workspace_ref` are not authority inputs. Missing,
unsupported, remote, malformed, oversized, nonmatching, or unresolved multi-repository roots fail as
`SESSION_CONFLICT` with `reason_code: repository_identity_required` before the service handshake;
the bound locator is retained only in that bridge's private client slot and revalidated before
each workflow call. A `notifications/roots/list_changed` notification retires the slot and requires
a fresh MCP session,
so one process cannot cross repository authorities. The bridge continues to advertise the same
tools/resources surface; roots are a client-to-server locator exchange, not a new FinishUP tool or
server capability. The public `workspace_ref` remains the caller's task-attachment selector and
the guidance convention is still to set it to the open repository root; the native roots binding
does not rewrite or reject a mismatching public ref. Such a mismatch can leave a session safely
bound to the host root while normal create/attach lookup semantics continue to use the caller's
ref pair. Hook auto-attach, queue admission, and mapping failures remain separate host lifecycle
concerns.

### Claude Code local project harness contract (issue #154)

Claude Code is a native dual target and is not an Agent Plugins consumer. The initial cell is
exactly Claude Code CLI/local process/project scope/private directory marketplace, capability
profile `claude-code-cli-local-project-2.1.241`, macOS arm64, and the fixture's exact executable
digest. `HostSurface.CLAUDE_CODE` does not imply Desktop local/SSH, Desktop remote, web/cloud,
synced, managed/user/local scope, Agent SDK, or headless support.

`ClaudeCodePluginTarget` binds absolute trusted project, Claude config, cache, marketplace, and
resolved executable paths; exact `ClaudeCodeCapabilityIdentity(version, executable_digest,
os_name, architecture)`; scope exactly `project`; and marketplace name exactly `finishup-local`.
Representations redact every path. The cache root must equal `<claude_config_root>/plugins/cache`.
Preview admits any parseable Claude version at or above `CLAUDE_CODE_MINIMUM_VERSION` (`2.1.233`)
and reports `version_provenance`: `tested` for an exactly proven cell
(`CLAUDE_CODE_HARNESS_PROFILE.supported_versions`, currently `2.1.241`), `untested` otherwise
(issue #656); a version below the floor is refused as `format_unsupported` with
`version_unsupported`/`minimum_version`. An `untested` host is admitted but never promoted to a
proven cell. Preview also re-hashes the executable to detect stale identity, and refuses with
`recovery_required` while interrupted stage/rollback material remains beside the marketplace source,
before any mutation.

`ClaudeCodePluginArtifact` contains one `PortablePluginPlan`, sorted native member mapping,
generated strict marketplace manifest, separate artifact/marketplace digests, the exact bound
`yoetz_launcher`, and a `development` flag. Its format is
exactly `claude_code_plugin_native`. The plugin members are `.claude-plugin/plugin.json`,
`skills/finishup/SKILL.md`, five byte-identical references, `hooks/hooks.json`, and optional
plugin-owned `.mcp.json`. Agents, commands, workflows, LSP, monitors, themes, output styles,
dependencies, channels, `bin`, `settings.json`, and `userConfig` are absent. The source marker is
`yoetz.claude-code-marketplace-install/2` and contains only structural plan/inventory/digest/launcher
fields; version 1 markers (no launcher) remain readable for status/remove and are never written.

Every hook command and the plugin-owned `.mcp.json` entry launch the exact installation that
rendered the artifact — the shared `finishup.adapters.integrations.launcher` helper resolves the invoking
console script (or `python -m finishup` as `(interpreter, "-m", "finishup")`) to an absolute executable plus
fixed arguments — never a bare `finishup` PATH lookup, so the bridge, hook process, and on-demand service
cannot come from different installations. The launcher is part of the artifact digest. MCP route
observation recognizes an exact FinishUP route as either a hand-written bare `finishup` command or the
artifact's exact launcher, each followed by the exact `mcp serve` arguments; any other command or
argument shape is `foreign`.

`render_claude_code_plugin(development_enabled=True)` produces the development carrier: identical
bytes except `defaultEnabled:true`, a distinct digest, and `development=True`. Only
`export_claude_code_plugin` consumes it — writing the plugin root plus a
`yoetz.claude-code-plugin-export/1` marker into a not-yet-existing owner-only directory for
`claude --plugin-dir`, with no Claude settings, marketplace, cache, or review authority involved —
and preview refuses it (`source_invalid`). A development export earns no marketplace-installed
proof facet.

`ClaudeCodePluginAction` is `install|update|enable|disable|remove|noop`; callers cannot request
`noop`. `ClaudeCodePluginPreview` carries request/action, before state, target/current state,
artifact/marketplace/preview digests, intended and observed MCP ownership/route, and sorted warnings.
The digest binds scope, marketplace, exact host identity, current source/install/version/settings/
enabled/MCP state, a `host_state_digest` over the four host-owned read-back files, and future bytes.
`ClaudeCodePluginResult` carries request/action/operation,
before/after state, preview/artifact/installed digests, enabled state, and only managed source member
names. `ClaudeCodePluginStatus` keeps source/cache/marketplace/list/enablement and every
`PluginProofFacet` separate; `loaded_root_digest` remains null until session-scoped evidence exists,
and `host_activation` is proven only when a validated session observation coincides with exact
installed bytes, discovery, marketplace registration, and enabled state — a session init alone (for
example a development `--plugin-dir` run) earns no marketplace-installed activation proof.

Every mutation consumes the exact `plugin_artifact_apply` pending plus the per-platform scoped
OS-authenticated presence cell described for Cursor above (macOS LocalAuthentication, Linux and WSL
2 PAM through the trusted console, otherwise fail closed); `--accept` alone is not authority.
Install generates/safely swaps only the private source, adds the project marketplace, and asks
Claude to install the qualified plugin; exact read-back must show disabled default and matching
cache/version. Update requires a marker-valid source/discovered install, replaces only managed
source bytes, then invokes marketplace/plugin update. Enable and disable alter only Claude's
effective project setting. Remove invokes qualified project uninstall with `--keep-data`, removes
the project marketplace, and deletes only exact marker-valid source. Replacement and removal
revalidate the displaced tree after it is renamed out of the public path — when nothing can swap it
any more — and destroy only a marker-valid managed tree; content created or modified during the
authority or host-command window is restored untouched and the mutation refused. Any post-mutation
state the independent read-back cannot confirm is `outcome_unknown` regardless of the subprocess
exit code (`refused` describes only safe pre-mutation rejection); status surfaces leftover
stage/rollback material as `recovery_required` with `outcome_unknown`, and no host-owned
settings/cache rollback is guessed.

`ClaudeCodeMcpSource` is exactly
`local|project|user|plugin|claude_ai_connector`, ordered by Claude precedence. Observation reads
local/user `.claude.json`, project `.mcp.json`, plugin `.mcp.json`, and an explicitly supplied
connector row. Both the `finishup` name and any differently named exact FinishUP route are ownership
candidates. The winner is informational: plugin plus external is `dual`, repeated same-class
owners are `ambiguous`, non-exact same-name configuration is `foreign`, and unreadable reachable
state is unobserved `ambiguous`. Effective route is non-null only for one exact external or plugin
owner. Scoped runtime identities are server `plugin:finishup:finishup` and tools
`mcp__plugin_finishup_finishup__<operation>`; bare names are negative controls.
`ClaudeCodeMcpObservation.host_admission_supported` is true only for one exact external or plugin
route whose configured server key is exactly `finishup`; an exact route under another alias remains
observable for ownership but cannot be mapped to a fixed permission-rule name and therefore makes
an admission grant refuse with `owner_required` rather than writing the wrong rule. The flag is
name-mappability only and deliberately independent of the route profile: a strict route keeps it
true, and the policy-route requirement is enforced separately at grant, which refuses
`route_not_policy`.

The rendered artifact carries the five candidate observation hooks
(`PostToolUse|PostToolUseFailure|SessionEnd|SessionStart|Stop`) plus a `PermissionDenied` hook
matched to exactly the external `mcp__finishup__check` and plugin-owned
`mcp__plugin_finishup_finishup__check` names. It produces no observation and records
one payload-free `hook_diagnostics` reason, `host_auto_review_denied` (`source` `auto_mode` or
absent) or `host_permission_rule_denied` (`permission_rule|hook`), on the `PermissionDenied`
event (issue #467), and any other tool name records nothing and emits `{}`. For the scoped
`check` its stdout is the **host-hold advisory** (`cli/host_hold_advisory.py`, issue #857):
`hookSpecificOutput.{hookEventName, retry}` and `systemMessage` (user-visible fixed text from
closed tokens only, ≤ 2 000 chars). Claude Code 2.1.281 drops `additionalContext` on this event;
the model receives only the host's retry cue. `read_host_hold_facts` reads the repository grant
through the bound service with one `GRANT_READ_DEADLINE_MS` = 2 500 ms budget covering connection,
`privacy_get_setup`, and cleanup. `GrantReadReason` is `grant_confirmed` only when `grant_state =
granted` and `llm_inference` is enabled; other outcomes remain closed unconfirmed reasons.

SessionStart's separate `cli/host_startup_advisory.py` can append a fresh grant snapshot and the
host-specific admission command on Codex/Claude `additionalContext` or Cursor `additional_context`.
It names absent project admission, explicitly leaves route and host approval unconfirmed, and
introduces no retry. Existing context keeps priority; no partial notice is emitted. The read uses
up to 500 ms of spare hook budget, including connect/RPC/close. Local-only, deferred, out-of-budget,
out-of-space, unreadable-grant and non-absent-admission paths remain silent. No bridge route cache
is created: a host name is not a current transport identity. This notice requires a bound workspace;
the ordinary shared path also requires active observation consent. See ADR-018's correction.

`note_retry_offer` uses an owner-only `observation/host-hold-retries.json` ledger of up to 64
session digests and answers `first|repeat|unrecorded`. Full or damaged ledgers never forget a
prior offer; unsafe files and lock contention fail closed. `classifier_verdict_present` rejects
unknown sources, missing reasons, legacy `no_verdict`, the current no-verdict reason prefix and
`Classifier unavailable`. `compose_host_hold_advisory` emits retry only for a confirmed grant,
a recognized verdict and a durably recorded first offer. The hook emits no
permission decision and edits no host file. But the
`CLAUDE_CODE_HARNESS_PROFILE` hook capability cell advertises no observation events: the recorded
evidence case observed no accepted observation, so the cell stays unpopulated until each event has
installed-host delivery, privacy, and accepted-observation evidence. `ObservationSource` adds
`claude_hook`; local-control `2.2.0` appends that source and coverage row to immutable `2.1.0`.
Ingress accepts only closed lifecycle actions, exact scoped workflow tool identity (the renderer
matcher and ingress allowlist derive from the one `FINISHUP_WORKFLOW_TOOL_NAMES` set, including
`read_guidance`), bounded session/correlation token, a fail-closed capability profile mapped from an
exact payload-evidenced Claude version (`untested` otherwise), and host-derived success. It discards raw
prompt/response/transcript/path/cwd/command/tool input/tool output/result/error/permission/secret
content before storage, performs no Claude transcript reconciliation, and is always fail-soft. One
closed exception establishes routing rather than content observation: an exact successful scoped
`start` `PostToolUse` may transiently parse the structured result or one bounded MCP text block and
persist only validated task/session/writer identifiers plus the frontier token in the existing
lifecycle mapping. No result bytes or result-derived prose enter the observation envelope, store,
diagnostics, or errors.
Only consented accepted evidence earns coverage.

## 11. Application (`application/`)

`Application` is a service-internal frozen dataclass wiring all use-case ports, `PrivacyCoordinator`,
and `VerificationPolicy`. `VerificationPolicy(semantic, max_findings, finding_attempt_budget)` is
the immutable application-safe snapshot of effective verification config: `semantic` is exactly
`disabled|optional|required`, `max_findings` is an exact non-bool integer in `1..10`,
`finding_attempt_budget` is an exact non-bool integer in `1..50` (default 5; issue #905), and its
derived default check mode is respectively
`deterministic_only|semantic_if_configured|semantic_required`.

The same module owns `ProjectionRenderMode(human_readable|machine_readable)`, frozen
`ClientProjectionContext(client_kind, render_mode, output_is_controlling_tty, owner_view=False)`,
`resolve_client_disclosure_sink`, and `ProjectedControlBody`. The projected-body type is exactly
the six operation result types plus `JsonObject` support results. The sink resolver returns
`local_human_view` only for an authenticated `cli` or `ui` context whose `owner_view` the daemon set
after consuming an `owner_receipt_view` grant; every other context, including human-readable
rendering to a controlling TTY, returns `agent_context`.
The context is service-internal, carries no caller-named sink, must match the authenticated session
kind, and defaults fail-safe to machine-readable/non-TTY when trusted presentation facts are
absent. The daemon first obtains catalog-backed `Application.projection_binding_facts(...)`, then
`Application.project_result_for_client(context, binding, result)` is the only route from a
content-capable internal result to an ordinary serialized success.
Project title and description hydration checks the exact source-owned text reference, route,
membership generation, and source disclosure policy before loading text, then revalidates after
the recipient projection decision. A source denial contributes a content-free candidate with
`source_disclosure_permitted=false`; this trusted internal restriction can only remove authority.
The ordinary privacy classifier and audit record the blocked category and exact omission pointer.
Recipient policy, including self-authorship, cannot override this source restriction. The service
does not manufacture additional omissions or alter the recorded disclosure receipt after approval.
For repository privacy setup/effective/propose, `ControlProjectionBinding` additionally carries the
installation-keyed repository commitment from `ControlSession.repository_privacy_context`; the
scope resolver uses that trusted commitment to select the workspace policy and receipt scope.
It never reads a repository identity from the request body. An unbound session stays fail-safe at
machine scope.

One public async method
per operation: `start`, `publish_work`, `check`, `respond`, `status`, `receipt`, plus
`import_codex_jsonl` and `review` (support). All accept/return FinishUP request/result dataclasses
(`StartRequest/StartResult`, etc.), never SDK types. All expected failures leave as
`PublicOperationError`.

Every `status` success carries `closure_readiness(open_obligation_count,
unanswered_finding_count, receipt_blocking_finding_count, declared_obligation_count,
no_obligations_reason, blocking_conditions)` beside `import_status`, on every view.
`unanswered_finding_count` counts recorded findings with no recorded response, whatever a later
response's disposition; a rejection, waiver, or provenance dispute answers the finding on the
record and its own quality surfaces as a later finding. An observation-authored, non-actionable
finding of an allowlisted limitation kind (`is_observation_limitation`; for example the
"Observation coverage is incomplete or stale" advisory, including rows
recorded by earlier builds) is a disclosed coverage limitation, not response work: it never counts
here or in the compact `unanswered_findings` preview, so it never sets `findings_unanswered`. It
stays in `view=findings` with its own disposition and an explanation that names it a limitation,
keeps its resolution requirements (it does not become resolvable), and stays on the receipt with
its coverage; an optional acknowledgement is recorded like any response and carried there (#911).
A readable finding that a later qualifying check already resolved, with no response, is
`verified_resolved`, a final state `respond` refuses, so it is not response work either and never
sets `findings_unanswered` (pilot blocker: otherwise repairing before answering left an item no
action could clear).
`kernel/projections.unanswered_finding_ids` is the single rule for the status counter, the compact
preview, closure readiness, and the durable SQLite mirror. `receipt_blocking_finding_count` selects the
newest readable finding per receipt issue key and counts the actionable ones that
`finding_is_resolved` does not report resolved. It never decreases merely because a response was
recorded; only a later qualifying check of the repaired record (the finding-view rule above)
resolves a row, and the same read sets the receipt's `resolved` state and the status finding
row's `resolved`, so the three surfaces cannot disagree.
The compact singleton carries the same two completion-scope fields beside its current plan locator,
both counters, and an `unanswered_findings` preview. Its `blocking_conditions` are exactly
`obligations_open|findings_unanswered|receipt_findings_unresolved|no_plan_published|
no_obligations_declared|projection_stale|coverage_gaps_declared|readiness_unknown`. It is derived
per request from the compact projection and a current, read-only comparison of accepted catalog
children with the parent's recorded dependency manifest. Child blockers, including
`lineage_manifest_not_recorded` and `lineage_manifest_state_changed`, appear in the status envelope's
`gaps` and coverage and set `coverage_gaps_declared` on every view, including compact. An unavailable
comparison contributes `lineage_readiness_unavailable`; it cannot make the parent look ready.
Pending child annotations do not block. These current advisory facts never refresh a manifest,
open a child bundle, change a recorded check, or strengthen a receipt. Reading readiness records
nothing, creates no verdict or IDs, and never strengthens coverage.

When the latest persisted check has test-edit totals, the compact singleton may also carry
`latest_check_test_edits`. This path-free structural summary includes the checked frontier,
`read_availability` (`available`, `unknown`, or `unavailable`), `examined`, `baseline_known`, and
the modified, renamed, deleted, skipped, unjustified, and unknown counts. `unavailable` means no
admitted capture was available; `unknown` means the capture or baseline was incomplete. It never
includes a repository path or captured content.

The compact singleton may also carry `latest_check` (status-result 1.4.0, optional, absent when no
check is recorded; issue #1027, ADR-044): `check_event_id` (the recorded `check_recorded` event the
projection's latest tested state points at), `checked_frontier` (the frontier that check examined)
and `verdict` (`action_required|incomplete_check|insufficient_coverage|no_issue_detected`). Each
`obligations` item may carry `in_current_plan` (status-result 1.4.0, optional): `true` exactly when
the obligation is in the current plan's effective scope (published, not waived, not superseded by a
later plan revision; `task_facts.effective_obligations`), `false` for a historical one the view also
lists, absent when the plan scope cannot be read. It is a
pointer, not a readiness claim; a check recorded later than `checked_frontier` is not reflected
until the projection's latest tested state advances. The CLI status render prints it as
`Latest check: <verdict>; checked frontier <n>; event <id>`.

Every projection view reports one coverage definition in the status envelope (ADR-032, issue
#913): `coverage` and `gaps` are the task coverage the compact view reports — the applicable
check folded over the newest record, plus projection and completion-scope gaps — not the newest
record's own envelope coverage. A non-compact view reads the compact page once and shares it with
closure readiness; if that page cannot be read, the view reports its own page coverage with
`ledger_freshness=unknown` rather than a cleaner value. Advice, candidate-finding, lineage and
project views keep their own documented coverage.

`closure_readiness` is also a checklist (ADR-032, issue #913). This build emits it on every
status success; on the unreleased status-result 1.4.0 wire the six checklist fields are optional
as a whole (absent for a result shaped by an earlier 0.3 build, never partial or null).
`closure_readiness.admissible_verification` is also optional on that unreleased 1.4.0 result
(absent when no flagged obligation has an observed verification link; absence never means a cited
id is linked). `closure_readiness.closing_material_frontier` is optional on the same wire
(omitted by an earlier build; `"0"` means no material delta has been recorded).
Beside the
unchanged `blocking_conditions` it carries `state` (`action_required|ready|ready_with_limitations|unknown`),
`gap_classification_version` (`"8"` since `deliverable_references_undeclared_file` became an
agent-actionable task fact (#1044, ADR-035 amendment); `"7"` when the table became a view of
`kernel.gap_effect` and added the
readiness token `finding_rejection_awaiting_ruling` (ADR-046) and the standing task-fact
disclosures `planned_verification_matched_by_prefix` and `declared_output_not_reviewable`
(ADR-045); `"5"` added the standing code
`finding_disputed_after_rebuttal` (issue #1020); `"4"` added `assumption_disclosed`,
`verification_limit_disclosed` and `finding_premise_disputed` (issues #995, #984); `"3"` added
`finding_self_verified`; the wire still admits `"1"`–`"4"` from an earlier 0.3 build),
and three groups. `agent_actionable` lists, in order, the
agent conditions present (`obligations_open`, `findings_unanswered`, `receipt_findings_unresolved`
only for findings whose closure class is `agent_work` (an acknowledged requirement is
`settled_unmet`: final, so the state stays `ready_with_limitations`, and counted in
`receipt_blocking_finding_count`; a `self_verified` finding is `settled_disclosed` and disclosed as
the standing code `finding_self_verified`; ADR-046), `finding_rejection_awaiting_ruling` for a
rejected finding that waits for a reviewer ruling (a check is the next move),
`no_plan_published`, `no_obligations_declared`, `projection_stale`), then `check_in_progress`
while a check holds the session frontier (read at the head through the ledger's
`has_active_frozen_case`; an unanswerable probe counts as in flight), then `check_not_recorded` or
`check_not_applicable` from the receipt applicability rule (an observed deliverable or workspace edit
after the check counts; FinishUP's own calls, host-native reads, commands whose fingerprint saw the
workspace unchanged and host bookkeeping do not, `kernel/later_material`, tb4n3 RC-6, PR #1080), then `closing_review_required` (issue
#976: AI-powered review is required on the route, or completed on the task, or was deferred before
the first material edit by a check whose route requires it (#1046), and no completed final-phase
review, or undeliverable review attempt, is current since the last material task or verification
change — an observed edit or shell write, an observed command or its result that is not shown to
leave the workspace unchanged, a cooperative edit or command, or a `decision_recorded` whose `review_mode` is set (ADR-049); a
decision that leaves `review_mode` unset, and the rest of bookkeeping and dispositions, do not count
(`kernel/closing_review_delta`, #1079). An observed shell command, or its result, is that change
unless the hook's before/after workspace fingerprint recorded the workspace `unchanged` across it
(PR #1080 round 5; ADR-033 amendment): the structural `workspace_effect` token
(`unchanged|changed|unavailable`) the live `PreToolUse`/`PostToolUse` hook pair derives, which the
result summary carries as ` (workspace unchanged|changed|unverified)` and
`kernel/later_material.workspace_effects` reads back only from service-stamped results. An
unchanged command still counts when it is a verification run (a `test|build|lint|typecheck`
runner, or a run of a command an effective obligation requests,
`task_facts.requested_verification_run_events`) or a package install (`install` runtime token).
A command without the fact (no pre-call snapshot, a call the host has not reported as ended, a
workspace beyond the walk bound, an unreadable directory, a legacy-spool or session-stream
observation, a record from before the fact) is material; the Stop text names it as a command
FinishUP could not establish left the workspace unchanged. Command text never decides: the
round-3/4 read shapes (`date -u`, bounded `sed -n`, `rg`, `git status`, FinishUP CLI verbs) keep
their runner class only for failure accounting and advice. Another observed tool that is not
FinishUP's own and not a host-native read counts when its result reports `changed`. Workspace
write facts still win. Receipt, work-close and lifecycle events do not re-arm the review.
Native Codex runner classification unwraps one ordinary host shell, retaining nested executable
paths separately from keyed identity normalization. Generic finalizer and
regression names grant no verification credit. Explicitly requested verification commands use
the existing ADR-045 matching and completed-result ordering, including a completed command the
agent later retrieves through `write_stdin`. Masked shell compositions retain their unknown-part-outcome gap.
An unchanged newest check that failed with
`coordinator_failure` is current and adds the standing code `semantic_coordinator_failure` instead
of asking for the same closing review; an actionable
`semantic_review_not_requested` takes its place unless the latest check so deferred the review),
then every actionable gap code and
`unclassified_gap:<code>` for a base code the running build does not know.
`standing_limitations` lists the classified standing base codes (plus
`check_payload_unavailable`). `acknowledged_not_done` lists up to 64 obligation and finding ids
recorded as not done, and `acknowledged_not_done_count` counts them all. An obligation is recorded as not done
by `obligation_published` 1.1.0 with `status: "acknowledged_not_done"` and a required
`acknowledged_not_done_reason` (1..4096 UTF-8 bytes; 1.0.0 refuses that status; issue #997,
ADR-032 slice C); it is then not open and not resolved, outside completion coverage (a completion
claim that omits it raises no `completion_plan_not_claimed`; one that names it still raises
`completion_with_open_obligations`; ADR-041), a later
publication of it with `open` or `resolved` takes it back, and the obligations view shows it as
`open`. A `decision_recorded` statement line `finishup-assumption:<obligation id>` or
`finishup-verification-limit:<obligation id>` (issue #995, ADR-033) adds the standing code
`assumption_disclosed` or `verification_limit_disclosed`; it never blocks or resolves anything,
and superseding the decision withdraws it. `finding_premise_disputed` (D7a) discloses
acknowledged findings the review says the task requires; the Stop gate asks about them once. The
optional `acknowledged_obligation_count` counts acknowledged obligations without truncation;
`open_obligation_count` never includes them. The Stop gate challenges each acknowledged obligation
once (`acknowledgement_recheck`), and the closing review lists them in its blocker question. Every recorded page gap
is classified by its base code through `finishup.kernel.closure_readiness.GAP_CLASSIFICATION`. A live
lineage token from the catalog comparison is disclosed only when a recorded evaluation already
carries its code (`live_lineage_blockers`; `lineage_child_read_gap` is recorded as
`lineage_child_unavailable`); otherwise it is agent-actionable whatever its class, because a
receipt folds recorded lineage only and cannot disclose it yet. No gap is dropped from `gaps` or
`known_gaps`. The optional `check_cause` (`StatusCheckCauseModel`, present only beside the token it explains: `effect`
`superseded|bounds_conclusion`, `event_id`, `ledger_sequence`, `check_event_id`,
`check_subject_frontier`, `family`, `material_class`, `rule`, optional `tool`) names the first later
record that decided it; MCP text, the CLI and the terminal interface render the one frozen sentence
`readiness_text.check_cause_sentence`. The bounded MCP text on every status view reserves its core
first (view and frontier, the closure state, the stop instruction, the agent-actionable items, the
operation-progress fallback), then grants the cause (the full sentence, else its short form: record
and check frontier, no id or rule), then every boilerplate sentence (the counts sentence of the full
directive, the generic closure sentence, the operation-progress text); the cause is never required,
so it cannot displace core (`mcp/summaries.py` `_check_cause_part`, `compose_parts`). `state` is `unknown` exactly with `readiness_unknown`
(then `agent_actionable` is `("readiness_unknown",)` and the other groups are empty); otherwise it
is `action_required` while `agent_actionable` is non-empty, `ready_with_limitations` when only
standing or acknowledged entries remain, and `ready` when nothing remains. The five agent
conditions other than `receipt_findings_unresolved` appear in `agent_actionable` exactly when they
appear in `blocking_conditions`. `semantic_review_not_requested` is agent-actionable only when the
effective verification policy is `required`, the status read is not served by a strict MCP route
(which never dispatches AI-powered review, ADR-018), and no check whose AI-powered review succeeded
has been recorded without a later material change; on a strict route it is a standing limitation.
Status reads without a route (CLI, terminal interface, closure preparation) use the policy-route
rule, so one session can read `ready_with_limitations` to a strict MCP client and
`action_required` in the CLI or terminal interface: readiness is per caller, and the CLI can run
the required review on the policy route. Coverage, `known_gaps`, verdicts and receipts do not
differ. The inputs the compact row cannot carry travel on the internal compact
`ProjectionPage.readiness_facts` (`ClosureReadinessFacts`: check applicability,
AI-powered review currency, receipt-blocking and acknowledged finding ids, acknowledged obligation
ids), derived per request from the projection and record prefix at the requested frontier and
never cached across frontiers. A compact page without those facts yields `readiness_unknown`, never
a stop state. MCP text, the CLI and the terminal interface render the state's
frozen directive from `finishup.protocol.readiness_text`; for `ready_with_limitations` it is "Nothing
further to do. N standing limitation(s) and M acknowledged item(s) will be disclosed on the
receipt. Request the receipt." Readiness never recounts findings: "this finding still needs an answer" has the one source
`kernel.projections.unanswered_finding_count`, read through the compact row.
`findings_unanswered` identifies response work still to do;
`receipt_findings_unresolved` is a persistent conclusion bound, not an instruction to respond
again. Once every readable finding is answered, the latter condition remains and tells the caller
that a receipt may be requested but cannot conclude `no_unresolved_deterministic_findings`.

#### The closure verdict (tb4n3 RC-3, issue #1026, ADR-046)

Every surface that says whether an item still bounds closure reads one verdict, computed from the
ledger prefix and never stored. Names:

- `finishup.kernel.closure_class`: `FindingClosureClass` (`agent_work|awaiting_ruling|settled_unmet|settled_disclosed|resolved`),
  `ObligationClosureClass` (`agent_work|settled_unmet|settled_disclosed|resolved`), `ReceiptEffect`
  (`none|insufficient_coverage|unresolved_findings_remain`), the closed `FINDING_BASES` /
  `OBLIGATION_BASES` tables (basis -> class and effect), `NEXT_ACTIONS` (`repair|recheck|reject|acknowledge|acknowledge_not_done|self_verify|reopen|none`),
  `finding_closure(s)`, `obligation_closures`, `ClosureCounts`, `Recheck`. A basis token names the row
  (`open_unanswered`, `open_answered`, `reopened`, `limitation_requested`, `rejected_awaiting_ruling`,
  `rejected_review_unavailable`, `acknowledged_not_done_requirement`, `acknowledged_not_done_bookkeeping`,
  `self_verified`, `disputed_after_rebuttal`, `rejection_accepted`, `limitation_disclosed`,
  `limitation_acknowledged_not_done` (`settled_unmet`: a limitation request the agent answered
  `acknowledged_not_done`, owner decision 2026-10-12),
  `absence_proved`, `absence_proved_after_acknowledged_not_done`, `absence_proved_after_self_verified`).
- `finishup.kernel.gap_effect`: `GAP_EFFECT_TABLE` (one row per recorded gap code and the readiness-only
  tokens), `GapContext`, `GapEffectKind` (`actionable|standing_bounding|disclosed|historical`),
  `gap_effect`, `judge_gaps`. `GAP_CLASSIFICATION` is a view of it; `GAP_CLASSIFICATION_VERSION`
  is `"8"` (#1044: rule G0c makes `deliverable_references_undeclared_file` actionable on both
  routes).
- `finishup.kernel.receipt_prediction.predict_receipt_conclusion(ClosureBasis)`: the receipt's
  conclusion rules R1-R10 and their reason codes. `receipt_builder.build_receipt` calls it, so the
  receipt label and every prediction are one function over one context.
- `finishup.kernel.closure_verdict.closure_verdict`: the composition (classes, judged gaps, readiness
  split, prediction, counters, rechecks). `finishup.application.closure_basis.load_closure_basis`
  rebuilds the receipt's context at a frontier for status and the check (memoized per session and
  frontier, valid only while the adapter's projection object is unchanged). An unpinned status
  read that loses that frontier to a material append re-reads the whole basis at the latest
  frontier, immediately, at most twice (ADR-046 amendment of 2026-10-15). `basis_frontier` is the
  frontier that read landed on. A status cursor or `at_frontier` is never moved; the prediction
  is omitted instead. The ledger's suffix check is unchanged: an observation-authored extension
  or a second receipt rendering still leaves the asked-for frontier valid.

Wire (all optional on the unreleased 1.4.0 results; absent from an earlier 0.3 build and whenever
the basis could not be read):

- `status` `closure_readiness`: `predicted_receipt {conclusion, reasons[{code, rule, count, refs[<=3],
  since_frontier?}], reason_total, basis_frontier, provisional}`;
  `finding_counts {to_do, awaiting_ruling, unmet, disclosed, to_disclose, self_verify_eligible}`
  (`to_do` includes `awaiting_ruling`; `to_disclose` is never inside `to_do`);
  `obligation_counts {open, acknowledged, disclosed}`;
  `awaiting_ruling_findings [{finding_id, since_frontier}]` (<= 8, by id; exactly the findings
  counted in `finding_counts.awaiting_ruling`, up to the bound); `rechecks [{kind
  (acceptance|acknowledgement|blocker|premise), key (accept:<h8>|ack:<obl>|blocker:<obl>:<kind>|premise:<n>),
  subjects[<=8], rule, since_frontier}]`. Since tb4n5 (#1050, ADR-033 amendment of 2026-10-13)
  the `acceptance` entry names only the resolved obligations the ledger flags (rule
  `resolved_obligations_acceptance_risk`, key over that set; no entry when none is flagged):
  `finishup.kernel.acceptance_risk.acceptance_risk(projection, records, resolved) -> ((obligation,
  reasons), ...)` with the closed reasons `requested_item_never_attempted`,
  `evidence_not_linked_to_declared_items` and `evidence_self_asserted_only`, carried per request as
  `ClosureReadinessFacts.acceptance_risk_obligation_ids` (`None` on a hand-built fact set keeps
  every resolved obligation and the rule `resolved_obligations_acceptance_reread`). The alignment it
  reads is `finishup.kernel.evidence_alignment` (`declared_items`, `results_by_evidence`,
  `source_actions`, `evidence_sources`, `alignment_of`), shared with the inspection's
  `evidence_alignment`; the inventories are indexed once per call, each cited reference's
  source actions are resolved once per call (`source_cache`) and deduplicated by action id, and an
  identical call is answered from a one-entry memo (Stop's status deadline is 4,000 ms). The status
  directive's re-check note names the flagged set and, since #1079, the linked
  `finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` line or a
  `finishup-verification-limit:<obligation id>` line that answers it. The linked id counts only
  when `admissible_verification` (optional on the unreleased status-result 1.4.0) on this object
  names it for that obligation (an observed verification row — hook-captured or
  observation-captured evidence, or a result of an observed command — linked to the obligation,
  its requested target, or a claim that lists that obligation, at or before the frontier; a claim
  with empty `obligation_refs` lends nothing; an agent-asserted id is unattested). A bare `:met`
  and a generic all-met claim do not. A missing or foreign id is unattested. An obligation
  with a recorded `verification_limit` disclosure leaves the acceptance recheck; the receipt
  still lists it. `closing_material_frontier` (canonical uint, optional on this unreleased wire,
  emitted including `"0"` when computed) is the newest `closing_review_delta` ingestion sequence
  at or before the projection frontier. The Stop gate remembers an acceptance re-read against it.
  Omission (an earlier build) keeps the older once-per-obligation-set memory; `"0"` means none.
  `kernel.claim_verification.claim_verification_lines` renders that pairing in the receipt evidence
  section (JSON, markdown and text): one header and one line per flagged obligation,
  `<obligation id> <comma-joined reasons> verification_limit|verification_limit linked <ids>|linked <ids>|no_verification_limit`.
  `<ids>` are the admissible observed `evd_` or `res_` ids. A final-message
  line does not create the ledger link that line reports. `recheck_note(readiness, *, host=None)`
  is host-aware (#1050 follow-up, #1079): `None`, `codex` and `claude` name the linked line;
  `cursor` (no final message at Stop) never names `finishup-acceptance` and names a recorded limit
  or an evidence link instead; `generic` (the CLI and TUI, which do not know the agent's host)
  names which hosts read the line. `prepare_closure(..., host="generic")`
  passes it; the MCP bridge passes its host profile, and also to
  `render_safe_compact_summary_detailed(envelope, *, host=None)`, whose status and
  `closure_prepare` summaries read it through a render-scoped context (a direct builder call keeps
  the line). `receipt_blocking_finding_count` keeps its wire name and means
  `finding_counts.to_do + finding_counts.unmet`.
- `status view=findings` rows: `closure_class`, `closure_basis`, `next_actions`;
  `view=obligations` rows: `closure_class`, `closure_basis`.
- `check` `finding_checklist.counts`: `to_do`, `awaiting_ruling`, `unmet`, `disclosed`,
  `to_disclose` (the group travels together); items carry `closure_class` and `closure_basis`;
  `finding_checklist.next` and `overall_next.action` add `request_ruling` and `disclose_limitations`
  (owner decision 2026-10-12: the only remaining agent work is a reviewer's limitation request nobody
  answered; mixed with real work the value stays `work_open_findings`); `overall_next` adds
  `predicted_conclusion`.
- `receipt-document` 1.3.0 (additive, in place): `limitation_disclosed_finding_ids`,
  `conclusion_basis {reasons[{code, rule, count, refs, since_frontier?}], reason_total}`, and a gap
  `effect` (`bounds|disclosed`). A clean conclusion beside a limitation id or a bounding gap is
  invalid, and `reason_total` is zero exactly when the conclusion is clean.

Text (`finishup.protocol.readiness_text`): the owner-approved `readiness_directive` sentence is
unchanged; `predicted_receipt_variants` appends "The receipt will read X: <reasons>." (while work
remains: "A receipt requested now would read X: ..."); `closure_counts_variants` prints "Findings to
do: N (awaiting ruling: K); unmet (acknowledged requirements): M; disclosed: L; to disclose: J.";
`recheck_note` ("At Stop you will be asked once to re-read: ...") and `awaiting_ruling_variants`
name the announced re-reads and the findings that wait for a ruling. The MCP status text, the CLI,
the terminal panel and `closure_prepare` print them; no human surface prints "receipt-blocking".

No plan yields `no_plan_published`. A readable effective plan with declared count zero and no reason
yields `no_obligations_declared`; the same count with a typed reason clears that blocker while the
reason remains visible. A positive declared count has no completion-scope blocker when all effective
obligations are resolved. Compact omits its singleton when the task title is unreadable. Readiness
never fills an unreadable scope or count with zeros: all four counts and the reason are then `null`,
and `blocking_conditions` is exactly `("readiness_unknown",)`. Unknown is a bounded state, not a
default. Existing stale, unknown-event, missing-reference, redaction, and coverage-gap blockers
remain conservative.

Only `ServiceDaemon` constructs and calls this facade after lifecycle/vault
readiness and control admission; CLI, MCP, and UI call `ServiceClient` instead and cannot import
runtime composition. Backup/restore/migrate and Codex skill lifecycle are composed through the
separate `MaintenanceService` and `IntegrationService`; they are not methods on the six-operation
facade and are never MCP tools.

## 12. Adapters — key entry points

- `adapters/runtime.py`: `LocalBundleRuntime` is the concrete generation-fenced
  service-owned `BundleRuntimePort`; its factories own exact catalog-to-task composition and
  bounded lifetime without a per-client runtime mode.
- `adapters/control/unix_socket.py`: fixed owner-only AF_UNIX endpoint plus Linux `SO_PEERCRED` and
  macOS `getpeereid` peer authentication; filesystem permissions are defense in depth, not the sole
  identity check. Exact adapter values are `EndpointKind` (`control|secret|human_control`), opaque
  nonserializable `PeerIdentityHandle`, `AuthenticatedUnixStream`, `UnixEndpointListener`, and
  bounded adapter-only `LocalControlTransportError`. The fixed basenames are `control.sock`,
  `secret-ingress.sock`, and `human-control.sock`, beneath the verified platformdirs per-user
  runtime directory with `0700` parent/`0600` endpoints. Async bind/connect functions have no path
  overload or TCP fallback. Framing/schema/state-machine ownership remains in the ordinary and
  confidential protocol modules; these transport values never enter public workflow results.
  Ordinary-control connection admission is bounded: each accepted stream holds one of a fixed
  listener capacity (128) until the stream closes. The daemon enforces private wall-clock
  liveness bounds on that path (no wire fields, error reasons, configuration options, or public
  APIs): an ordinary-control client must complete the entire handshake — including partial-frame
  drip — within **5 seconds**, and after handshake a session with no active requests may remain
  inactive for at most **5 minutes** before the stream is closed and the admission slot is
  released. The inactive-session deadline starts immediately when no calls are active and only
  when the final call completes when calls are active; it covers a complete frame read so dripped
  partial bytes cannot retain capacity indefinitely. Active long-running calls are not cancelled
  merely because no additional frame arrives. Each control-result write is wall-clock bounded
  (**5 minutes**) so a stalled peer cannot keep a call marked in-flight (and idle-exempt) via
  send backpressure alone.
- `adapters/session_events.py`: positively tested lock/suspend monitoring. v0.1 exposes foreground
  `service run` only; user-service-manager installers and hidden client spawn are absent.
- `adapters/sqlite/connection.py`: `open_writer(path) -> apsw.Connection` (frozen PRAGMA + build
  verification), `open_read_only(path) -> apsw.Connection`; `verify_sqlite_build`,
  `verify_schema_identity`, `assert_active_bundle_generation`, and the bounded
  `SqliteWriterThread`. Shared values are `SqliteBuildReport`, `SchemaIdentity`, and
  `StorageUnsafeError`. Frozen constants are `REQUIRED_APSW_VERSION`, `REQUIRED_SQLITE_VERSION`,
  `REQUIRED_SQLITE_SOURCE_ID`, `FINISHUP_APPLICATION_ID`, `BUSY_TIMEOUT_MS`,
  `STATEMENT_CACHE_SIZE`, and `WRITER_QUEUE_DEPTH` as specified by the owning file/ADR-003.
- `adapters/sqlite/repository.py`: implements `LedgerPort` (bounded append transaction,
  operations/lease tables, AI-powered review job/attempt persistence, projections).
  `CheckpointReport` is the shared bounded result of `run_passive_checkpoint`.
- `adapters/sqlite/start_catalog.py`: implements `StartCatalogPort` (catalog schema + start state
  machine). Shared adapter values are `StartQuarantineCode`; exact functions
  `workspace_ref_commitment(lookup: MacKeyHandle, ...)` and
  `external_ref_commitment(lookup: MacKeyHandle, ...)`. `ports/start_catalog.py` owns the shared
  trailing-NUL byte constants `START_TITLE_DOMAIN`, `WORKSPACE_REF_DOMAIN`, and
  `EXTERNAL_REF_DOMAIN`; adapters import rather than redefine them.
- `adapters/sqlite/importer.py`: `SqliteImporter`, `SqliteImportPolicy`, and
  `IMPORT_SCHEMA_VERSION=1` own durable generation/lease-fenced importer state and plan/batch/
  report resume. `adapters/memory/importer.py` exports the parity types `MemoryImporter`,
  `MemoryImportState`, `MemoryImportPolicy`, and `MemoryImportFaultPoint`.
- `adapters/sqlite/maintenance.py`: implements `MaintenancePort`, constructs the neutral
  `ports/maintenance.py` `MaintenanceHandle` after the catalog generation CAS, and owns catalog
  route-switch recovery.
- `adapters/sqlite/migrations.py`: owns frozen shared `Migration` and `MigrationReport` values;
  exact `CATALOG_MIGRATIONS` and `BUNDLE_MIGRATIONS` registries (catalog `0001`, `0002`, then
  repository-authority `0003`; bundle `0001` through `0005`, unchanged by issue #139); and
  `initialize_catalog`, `initialize_bundle`,
  `run_migrations`, and
  `current_schema_version`. No caller may extend a registry dynamically or execute unregistered
  SQL bytes.
- `adapters/objects/envelope.py`: `yoetz-object/1` AEAD envelope encode/decode (ADR-004).
- `adapters/objects/encrypted_files.py`: implements `ObjectStorePort` (temp → fsync → rename →
  dir fsync; orphan GC with safety window and pin respect).
- `adapters/keys/os_keyring.py`, `adapters/keys/encrypted_vault.py`, and
  `adapters/keys/vault_passphrase.py`: implement service-vault backends; no client-side key store
  or secret environment/config fallback exists. The keyring adapter additionally owns
  `OSKeyringProbe`, `KeyringInitializationBinding`, `FirstInstallKeyringAuthority`, and the
  mutation-free `authorize_first_install` gate; existing-mode `load` never mints or requires that
  authority.
- `adapters/privacy/catalog.py`, `adapters/privacy/local_enforcer.py`, and
  `adapters/privacy/gateway.py`: implement policy/audit persistence, local classification and
  minimization, and the sole outbound gateway.
- `adapters/providers/openai_responses.py`, `adapters/providers/local_model.py`, and
  `adapters/providers/fake.py`: accept only the matching branch of `ApprovedProviderCase`—external
  adapters receive `ApprovedOutboundCase`; the local-model adapter receives
  `ApprovedLocalDisclosureCase`. The local-model adapter is exact AF_UNIX with no
  DNS/AF_INET/redirect/proxy/download fallback. The OpenAI adapter is credential-free at registry
  time; each physical attempt uses one per-attempt SDK client with a nonsecret sentinel plus a
  custom transport holding the body/profile/deadline-bound one-shot credential callback. No real
  credential enters SDK client/default-header state. Its registered shared credential validator is
  `validate_openai_credential(view)` with `OPENAI_CREDENTIAL_MIN_BYTES=16` and
  `OPENAI_CREDENTIAL_MAX_BYTES=512`: byte-exact token68 with trailing `=` only, no
  trim/normalization/log/network probe.
- `adapters/importers/codex_jsonl.py`: exact-version pure Codex line parser, sanitizer, and
  conservative candidate/gap mapper used by concrete import ports. Its shared identities are
  `CODEX_JSONL_MAPPING_VERSION`, `CODEX_OPAQUE_SCHEMA`, `SUPPORTED_CODEX_PROFILES`,
  `CodexCapabilityProfile`, and the `profile_for_codex_version`/`parse_codex_jsonl`/
  `plan_codex_mapping`/`materialize_codex_mapping`/`sanitize_codex_argv` pipeline.
- `adapters/importers/codex_plan.py`: production composition of that pure mapping pipeline with
  identifier allocation, encrypted batch-plan objects, canonical plan-manifest identity, and
  exact plan re-read for crash-safe SQLite resume.
- `adapters/integrations/codex_skill.py`: implements the trusted-project `IntegrationsPort`.
- `adapters/memory/`: reference `LedgerPort`/`StartCatalogPort`/`ObjectStorePort`/`ImporterPort`
  implementations used by conformance. Start routing exports `MemoryStartCatalogAdapter`,
  `MemoryStartCatalogState`, and `MemoryStartCatalogPolicy`.
- `adapters/mcp_stdio.py`: `bounded_stdio_server(max_json_bytes) -> (read_stream, write_stream)`
  async context manager with the limits frozen in §3 and ADR-005. `TransportFailure` is an
  adapter-private bounded failure and never crosses the SDK/application boundary.

## 13. Surfaces

- `cli/entry.py`: the installed console entry. It runs the `hooks observe|claude-observe|
  cursor-observe|spool` fast paths without loading typer, then refuses native Windows
  (`os.name == "nt"`) with the fixed `unsupported_platform` line and exit 20 — the exit an absent
  service already carries, because no FinishUP service can be reached from that process — before the
  full CLI loads; `version`, `--version`, `--help`, and `-h` are exempt (issue #709). Everything else
  falls through to `cli/app.py` unchanged.
- `service/daemon.py`: sole application/runtime/vault/privacy/provider composition owner and
  ordinary-control dispatcher; starts into explicit `ready` or `locked`. Its private canonical
  installation marker owns immutable vault-mode publication. Unlock calls only
  `activate_ready_application(service_generation, vault_generation)`, which revalidates both
  generations around the injected `ReadyApplicationFactory` and transfers application ownership
  before lifecycle publishes `ready`. Lifecycle drains close through the daemon relay in reverse
  order, so activation cannot race explicit/session/idle lock or stop.
- `service/client.py`: shared ordinary `ServiceClient` used by CLI, MCP, and future UI.
- `service/unlock.py`: server-side vault transition, throttle, and reauthentication coordinator; it
  has no terminal/client surface.
- `service/confidential_protocol.py` and `service/confidential_client.py`: pure YZH1/YZS1 contract
  plus client-safe connector/state machine; server authority is excluded transitively.
- `service/human_control.py`, `service/secret_ingress.py`, `cli/unlock.py`, and
  `cli/privacy_control.py`: server ceremony/secret consumers plus the separately trusted foreground
  TTY helpers; no ordinary approval flag/token or server import in the helper graph.
- `mcp/server.py`: low-level `Server("finishup")`, generated eight-tool registry (six workflow
  operations plus read-only `read_guidance` and `closure_prepare`), dispatch, prevalidated fallbacks
  (`LAST_RESORT_INTERNAL_ERROR_RESULT`), the initialize `instructions` string, a read-only
  guidance resource registry, and one `ServiceClient`; it owns no runtime/application/provider/key
  state. `read_guidance` does not use the service client. On the policy route
  `build_bridge_runtime` reads the service configuration once at startup, through the same
  tolerant loader the logging sink uses, only to render the AI-powered review destination disclosure
  (issue #479); it keeps no configuration state and the strict route never reads it.
- `mcp/descriptors.py`: the one owner of every agent-read string on the MCP surface — the six
  workflow tool names, `read_guidance`, `closure_prepare`, descriptions, and annotations, plus
  the `instructions` text.
  All are loaded from the packaged `guidance/` resources and verified against the resource manifest
  before use; none is composed at runtime from user, task, provider, or environment values, with one
  typed exception: the policy-route AI-powered review destination disclosure (issue #479, ADR-018
  destination-disclosure amendment), which `mcp/semantic_destination.py` renders from validated
  configuration through a closed catalog (`BUNDLED_ENDPOINT_HOSTS`, `DISCLOSABLE_PROVIDER_IDS`,
  `DISCLOSURE_PREFIX`, `MAX_DISCLOSURE_ENCODED_BYTES`, `disclose_semantic_destination()`,
  `read_semantic_destination_disclosure()`) and hands to `server_instructions()` only as a
  `SemanticDestinationDisclosure`. Absent or invalid configuration renders as unknown, an
  off-catalog endpoint profile as an unknown host, an unlisted provider id as unlisted, and a
  configured fallback endpoint beside the primary; strict instructions never carry it. Shared values
  are `ToolDescriptor`, `TOOL_DESCRIPTORS` (frozen `policy|strict` sets, each in the same order
  `tools/list` returns), `TOOL_DESCRIPTOR_DIGESTS`, `TOOL_DESCRIPTOR_SET_DIGEST`,
  `INITIALIZE_GUIDANCE_URIS`, `server_instructions()`, `ORDINARY_MCP_PUBLISH_EVENT_FAMILIES`,
  `PRESENTATION_INPUT_SCHEMA_BUDGETS`, `SERVER_INSTRUCTIONS_BUDGET`, `ADVERTISED_SURFACE_BUDGET`,
  and `advertised_surface_metrics()`. Generic-host initialize `instructions` carry the packaged
  `agent-instructions.md` document and then the route-profile suffix; every other guidance document
  is fetched on demand through `resources/read` or `read_guidance`. `server_instructions()` also
  takes `host_profile` (issue #789): the `claude` host receives `CLAUDE_CODE_INITIALIZE_INSTRUCTIONS`,
  a packaged body bounded by `CLAUDE_CODE_INSTRUCTIONS_BUDGET` (`observed_host_cap_chars` 2,048,
  the Claude Code desktop rendering cap recorded as an observed host fact in the Claude runbook;
  `packaged_max_chars` 964, derived so the body, the policy tail and `MAX_DISCLOSURE_ENCODED_BYTES`
  fit under the cap together; `max_chars` 2,048), with the same route tail and disclosure
  composition. The hosts in `COMPACT_INSTRUCTIONS_HOST_PROFILES` (`codex` and `cursor`, issue
  #918) receive `COMPACT_INITIALIZE_INSTRUCTIONS`, a host-neutral packaged summary bounded by
  `COMPACT_INSTRUCTIONS_BUDGET` (`packaged_max_encoded_bytes` 2,048; `max_encoded_bytes` adds the
  policy route line and tail plus the disclosure ceiling). It names every guidance URI and tells
  the agent to read `agent-instructions.md` with `read_guidance` before the first `start` and not
  to list resources, and keeps the start trigger, late-start, no-false-activation, consent,
  disclosure and coverage-wording rules; the per-step cadence is stated once, in that operating
  card (tb4n5 startup dedup, ADR-047); the route tail and disclosure are composed identically. The `generic`
  host, and any bare registration without `--host`, keeps the packaged document byte for byte. A
  host may charge the
  `instructions` string once per advertised tool — Codex copies it into every tool `description` —
  so `SERVER_INSTRUCTIONS_BUDGET` bounds that string per route profile and
  `ADVERTISED_SURFACE_BUDGET` bounds the aggregate of instructions-per-tool plus every description
  plus every advertised input schema (issue #300). Each budget carries `packaged_max_encoded_bytes`
  for the packaged text alone and `max_encoded_bytes`, which adds the disclosure ceiling (once per
  advertised tool in the aggregate); `advertised_surface_metrics()` accepts the disclosure so the
  longest admissible passage can be measured. `ToolDescriptor.input_schema` is the tools/list
  presentation projection (inlined common shapes, ordinary publish event families, minimal
  examples), preserving every catalogued schema-version branch for each advertised ordinary event
  family. Every shipped worked example validates against that presentation schema as well as catalog
  admission; `catalog_input_schema` / full catalog request schemas remain admission authority via
  `*.model_validate`. `ToolDescriptor.output_schema` adds the MCP-required literal root `type:
  object` to the equivalent success/error object union; `catalog_output_schema` preserves the exact
  frozen catalogue bundle, and result admission remains owned by `*.model_validate`. `status` and
  `read_guidance` and `closure_prepare` carry `readOnlyHint=true`; `receipt` carries `readOnlyHint=false` because it
  stages an object and appends a `receipt_recorded` event. Every tool carries an explicit
  `idempotentHint=true`. Policy `check` carries `openWorldHint=true`; strict `check` carries
  `openWorldHint=false` and names the external AI-powered review ceiling. The hint is inspectable
  metadata, not enforcement; the route constraint above is authoritative. Initialize instructions
  and MCP-originated `status(view=versions)` disclose the active profile; policy-route initialize
  instructions additionally disclose the startup-read AI-powered review destination. No descriptor
  carries a `destructiveHint`, because no FinishUP operation deletes recorded evidence. Descriptor and
  instruction text is bound by the same honesty lint as the guidance references: it may not say
  "verified", "proved", "authenticated", or "complete" except where the surrounding sentence states
  the exact sufficient coverage.
- `mcp/resources.py`: exposes the packaged harness-neutral guidance documents as MCP resources under
  stable `finishup://guidance/<name>` URIs for hosts that return the resource text. Initialize
  `instructions` always carry either `agent-instructions.md`, whose catalog paragraph names the
  other four URIs and the `resources/read` → `read_guidance` → installed-copy chain that reaches
  them, or a compact host body (#789, #918) that names all five URIs and `read_guidance`. A
  conformant `resources/read` payload does
  not mean the host delivered those bytes to the model; an empty body is not a fetch. A
  schema-valid `resources/list` payload likewise does not mean the host accepted the list; some
  Codex builds reject it with `Unexpected response type`. First-party
  skill install places the same files on disk as `references/<name>.md` beside the skill. Resources
  are static reviewed product bytes read through `importlib.resources` and digest-checked against
  the resource manifest; the registry
  is read-only, closed, and contains no ledger, task, projection, or user content. `resources/list`
  and `resources/read` both take `media_type` from that registry. It is therefore
  not a `LocalDisclosureSink` and creates no disclosure receipt.
- `cli/app.py`: Typer client surface with the six operations and registered support/service/privacy
  command trees; ordinary `--json`/stdin never carry unlock, credential, or reauthentication bytes.
  Includes the ADR-012 `setup` sub-app and `integrate <harness> mcp` sub-app; bare invocation
  prints help except the bounded interactive first-run case, which launches the wizard once.
- `cli/exits.py`: `exit_code_for(PublicErrorCode | success) -> int`.
- `config/models.py`: service-owned nonsecret service/storage/verification/logging and bounded
  lineage/delegation defaults plus a
  one-time denied first-run privacy seed and exact provider/local-model profile identifiers. The
  `[lineage]` settings are bounded `start_lease_seconds=60`, `attach_handle_ttl_seconds=300`,
  `contact_lost_recovery_seconds=300`, `max_depth=8`, and `max_fanout=32`; typed admission
  refusals enforce the depth and fan-out ceilings.  `max_fanout` accepts values through 64,
  matching the bounded child-manifest, check-preview, and receipt-child sections; larger values
  are rejected at configuration load rather than silently truncating lineage state.
  durable policy store—not config—owns the machine policy/ancestor ceilings. Privacy profiles are
  the `PrivacyProfile` enum; provider credentials and unlock/recovery material cannot be represented
  by config or environment. Ordinary clients never load this object. `release-probe` is available
  only to the service-start release harness and cannot loosen user policy. Shared config values are
  `FinishUpConfig`, `MinimalConfig`, `ConfigError`, `PathSafetyError`, `OwnerDeclaredEndpointConfig`,
  `SemanticFallbackConfig`, `primary_external_endpoint`, `fallback_external_endpoint`,
  `parse_https_origin`, and the exact endpoint profile ids `openai-responses`,
  `owner-declared-openai-responses` (ADR-014), `anthropic-openai-chat-completions`,
  `google-gemini-openai-chat-completions`, `openrouter-openai-chat-completions`,
  `xai-openai-chat-completions`, and `vercel-ai-gateway-openai-responses`. Every one of the seven
  resolves to exactly one runtime factory in `adapters/providers/factory.py`; the last five carry
  unknown data-use records and are
  configured, not live-verified, until their E-007 capability evidence exists. Constrained
  `https_origin` is the only owner-supplied locator; free `base_url` remains forbidden. Its
  composition-only
  `NetworkPolicy` values are exactly `denied|candidate_external|explicit_per_probe`;
  `SemanticPolicy` values are exactly
  `optional_local_model|optional_external|scripted_fake|no_implicit_model`.
- `config/write.py` / `config/privacy_desired.py`: atomic nonsecret TOML writers and privacy
  desired-state export/apply classification (widen never silent).
- `config/paths.py`: platformdirs-based `bundle_root()`, `catalog_path()`, path safety checks
  (rejects repo/sync/network/world-readable locations). Ambient roots use one application name for
  every root: `finishup`, or `yoetz` for a Yoetz-era installation adopted in place
  (`installation_naming()`, `installation_root_ambiguous`; ADR-048). Owns the one exact-target isolation
  contract (`ISOLATED_ROOT_ENV` = `FINISHUP_ISOLATED_ROOT`, ADR-026, issue #518; the legacy
  `YOETZ_ISOLATED_ROOT` is read when it is unset, and two different values raise
  `isolation_root_env_conflict`, ADR-048): when set, every
  identity root — `config_file_path()`, default `bundle_root()`, `state_dir()` (service
  lock/generation), `runtime_dir()` (control/secret/human-control endpoints), `cache_dir()`,
  `log_dir()` — derives from the validated `isolated_root()`; a set but unusable root fails
  closed as `PathSafetyError("isolation_root_invalid")` or the precise existing path-safety
  reason, never by falling back to ambient platform directories. `FINISHUP_STORAGE_DATA_DIR` and
  `storage.data_dir` alone are storage relocation, not isolation. The connection-free proof
  surface is `finishup service isolation --json` (`cli/isolation_status.py`), digest-only; it also
  reports `binding` (`IsolationBinding` = `ambient|environment|runtime_pin|environment_and_pin`)
  and `lifecycle` (`ReportedLifecycle` = `permanent|persistent|disposable|unlabeled`). Its JSON is
  `yoetz.isolation-report/1` (`protocol/isolation_report.py` `IsolationReportContract`, wire
  schema `service/isolation-report-1.0.0.schema.json`, golden vector
  `fixtures/service/isolation-report.case.json`; issue #567), which names two digest kinds
  apart. `path_identity` (`IsolationPathIdentity`) holds **path-identity digests** —
  `state_path_digest`, `endpoint_path_digest`, `storage_path_digest`, `config_path_digest`,
  `executable_path_digest`, each `path_identity_digest()` = SHA-256 over the canonical resolved
  path — which prove which target a runtime uses and never bind bytes. `config_content` is `null`
  unless `--content-digests` is passed; it is then one **byte-content observation**
  (`ContentObservation` = `PresentContentObservation | AbsentContentObservation`, produced by
  `observe_file_content()`): `path_digest`, `presence`
  (`ContentPresence` = `present|absent|not_regular|oversized|unreadable|unstable`),
  `content_digest` (SHA-256 of the bytes, `present` only), `size_bytes` (`present` only, at most
  `CONTENT_OBSERVATION_BYTE_LIMIT` = 16 MiB), and `observed_at` (RFC 3339 ms) — never content.
  Symlinks are followed, so `path_digest` is the target's identity; a read the file changes under
  is retried (`_STABLE_ATTEMPTS` = 3) and otherwise reported `unstable` without a digest. The
  untagged 0.2 output (an `identity` block whose `config_digest` was a path digest) is not a
  schema version and is no longer emitted; consumers detect it by the absent `schema` key.
  The runtime pin (ADR-028, issue #604) is the second, executable-bound source of the same root:
  `read_runtime_pin()` reads `RUNTIME_PIN_NAME` = `yoetz-instance-pin.json`
  (`RUNTIME_PIN_SCHEMA` = `yoetz.runtime-instance-pin/1`: exact `isolated_root` plus
  `installation_id`) from this process's `sys.prefix` into a `RuntimePin`; `isolated_root()`
  prefers the variable, falls back to the pin, and fails closed on a difference
  (`isolation_root_conflict`) or an unreadable, foreign-owned, group/world-writable, or
  malformed pin (`runtime_pin_invalid`); `isolation_binding()` names the selected source.
- `config/installation.py`: instance identity for independent installations (ADR-028).
  `InstanceIdentity` is the sealed `INSTANCE_IDENTITY_NAME` = `instance-identity.json`
  (`INSTANCE_IDENTITY_SCHEMA` = `yoetz.instance-identity/1`) beneath the state directory:
  `installation_id` (`ins_`), `lifecycle` (`InstanceLifecycle` = `persistent|disposable`; the
  everyday install is `permanent` by the marker's absence), `created_at`, optional `expires_at`
  (disposable only, ≤ 30 days), `source_ref` (exact 40/64-hex commit or null), `source_state`
  (`SourceState` = `clean|modified|unknown`), `package_version`, optional `package_digest`, and
  `runtime_prefix_digest`; canonical JSON, owner-only, domain-separated `record_digest`.
  `read_instance_identity()` returns `None` when absent and raises `InstanceIdentityError`
  (closed `reason`: `instance_identity_invalid|instance_expired|instance_exists|instance_absent|
  instance_not_disposable|instance_root_invalid|instance_root_too_long|instance_expiry_invalid|
  instance_lifecycle_requires_isolated_root|installation_identity_mismatch|
  instance_service_running|runtime_pin_conflict|runtime_pin_invalid|runtime_pin_unwritable`)
  otherwise; `write_instance_identity()` never overwrites; `verify_instance_binding()` is the
  service-start gate `service/daemon.py` runs before `acquire_singleton()`; `write_runtime_pin()` /
  `remove_runtime_pin()` own the pin file, and a pin that cannot be written (the prefix is not
  writable by the current user, or its disk is read-only or full) is `runtime_pin_unwritable` with
  no temporary file left behind. `cli/exits.py` maps the reasons through
  `INSTANCE_PUBLIC_CODES` (usage-shaped refusals exit 2, untrusted identity and an unwritable pin
  20 as `STORAGE_UNSAFE`, `instance_expired` 20 as `SERVICE_UNAVAILABLE`,
  `instance_service_running` 20 as `BUNDLE_BUSY`) and carries their remediation lines.
- `cli/instance.py`: `finishup instance create|status|dispose` (ADR-028). `create_instance()`
  creates one owner-only root (parent must exist; same path-safety gate; socket path bound
  `MAX_SOCKET_PATH_BYTES` = 100), seals the marker, and with `--bind-runtime` pins `sys.prefix`;
  it echoes the exact root once. Creation is whole or nothing: a refusal after the root exists
  (`runtime_pin_unwritable`, a pin conflict found at write time, a failed seal) first removes this
  call's own marker and the directories it created, each only when empty, so a retry after the
  repair succeeds (ADR-028, 2026-10-14 amendment). `instance_status()` is connection-free and digest-only: mode,
  binding, lifecycle, the isolation report's `path_identity` block, marker fields, `expired`, `runtime_provenance`
  (`matched|drifted|unrecorded`), `runtime_pin` (`bound|none`), and the lock-stamped
  `service_holder`. `dispose_instance()` removes exactly one marked persistent/disposable root:
  flock probe, SIGTERM to the stamped holder only, bounded wait (`STOP_WAIT_SECONDS` = 35),
  optional log retention to `<dir>/<installation_id>/`, `rmtree`, pin removal; repeat is a no-op.
- `observability/logging.py`: structured stderr logging, allowlisted fields only; shared `LogMode`
  is exactly `service|cli|mcp_stdio|confidential_helper` so each process installs only its bounded
  sink/filter profile.
  `observability/privacy.py`: canary-testable redaction helpers,
  `prepare_persisted_plaintext(data, *, canaries=())` (fail-closed scan before encrypted
  observation persistence: redact high-confidence spans, keep heuristic-only matches for egress
  redaction, withhold on canary, high-confidence saturation, or scanner failure),
  `redact_high_confidence_content(data)` (the same capture-time rule for hook, approved-check and
  import content),
  `session_id_hash(session_id, log_mac: MacKeyHandle)`, and
  `privacy_request_commitment(final_request_body, audit_mac: MacKeyHandle)`; raw MAC keys are never
  accepted.

## 14. Version identities

`version.py` exposes `VersionManifest`: package (`finishup`; manifests and receipts written before
the rename say `yoetz`, ADR-048), protocol (`0.1`), local control protocol (`1.0`),
privacy-policy schema (`1.1.0`), egress-receipt schema (`1.0.0`), engine (`0.1.0`), policy pack
versions, projection (`yoetz/0.1.0`), object format (`yoetz-object/1`), storage schema identities
(`catalog_schema_version` `5`, `bundle_schema_version` `14` — hand-versioned positive-decimal
counters stamped into every receipt's version block and pinned as `const` in the current
version-manifest schema), Python, APSW/SQLite source ID, MCP SDK, provider adapter versions.
Those two identities are not the SQLite `user_version`: that axis is owned by the ordered migration
registries under `migrations/` (`catalog/` and `bundle/`, one file per step), and
`adapters/sqlite/connection.py` compares a file's `user_version` against the registry head it was
built with — currently catalog 5 and bundle 14 — reporting `migration_required` when the file is
older and refusing `schema_newer_than_binary` when it is newer. A compatible package update runs
the storage-owned `BundleUpgradeCoordinator.run_before_ready` phase before READY; the existing
catalog `maintenance_operations` row records the `package_upgrade_migration` operation and its
backup/replay phases. Lazy bundle opening remains fail-closed until that phase completes.
Its shared support values are frozen `ResourceIdentity(name, media_type, size_bytes,
sha256_digest)` and `CapabilitySet(name, supported_versions, tested_versions, denied_versions)`.
Every capability collection is an exact ASCII-sorted set: membership is literal, with no SemVer
range, interpolation, nearest-version, or inferred-between-probes semantics.

`build_version_manifest` loads the installed
`finishup.resources/support/runtime-support.json` through `importlib.resources`, verifies that
resource's size/digest against the packaged resource manifest before trusting it, validates its
schema and canonical self-digest, and then binds its exact runtime/Codex/MCP support sets into the
manifest. Missing, malformed, mismatched, newer, or merely untested versions are not silently
supported and make write support fail closed as specified by `version.py`/startup diagnostics.
SQLite `application_id`: `0x594F4554` ("YOET", ADR-003).

`version --json` returns the resource-manifest digest and counts by default; explicit
`--resources` returns the bounded full per-resource identity list. Optional unavailable components
serialize as `{status:"absent"}`, not overloaded `null`. MCP and CLI `status view=versions` reuse
the same live APSW/SQLite/Python/source-id probes via `build_status_version_slice_facts`; that
slice cannot represent `{status:"absent"}` so it uses the token `unavailable`. `release-probe` is CI-only via explicit
service-start environment/override authority and is invalid in user configuration files.

## 15. Registry ownership rule

This registry owns names and semantics that cross two or more modules, a public boundary, or an
adapter/conformance boundary. A file spec owns its private helper names and may refine an
algorithm without copying every local class/function here. If a nominal type appears in two
modules, if memory and SQLite must both implement it, or if a value is serialized, it belongs in
this registry first. This scope keeps one source of truth without turning the registry into an
index of private implementation details.


### Status projection snapshots and AI-powered review diagnostics (issues #674–#676)

Status row queries reuse the already validated immutable current projection. Historical queries
replay immutable prefixes off the event loop and retain at most eight frontier/view/session row
indexes per ledger snapshot. The exact frontier digest and projection version are checked before
reuse. A replacement record tuple invalidates the cache, including content/redaction reloads;
SQLite clones do not inherit it. The cache is transient and stores no independently authoritative
state. Workers never receive SQLite handles. Cancellation joins the worker, and filtering/cursor
selection stops after the requested limit plus one matching row. First access to a view still
builds its row index; large-query CPU cost and append/receipt cost are separate from responsiveness.

Every exceptional AI-powered review attempt diagnostic uses the original check request ID, an
allowlisted exception category and a structural stage. Stages distinguish claim/recovery, privacy
admission, dispatch entered (outcome uncertain), response mapping, response persistence and result
commit. Provider invocation catches preserve their existing unknown-outcome semantics. Primary
exception evidence is emitted before cleanup; cleanup records carry the same request join. Neither
missing diagnostics nor null provenance proves that no provider executed. Diagnostics are
best-effort; absence can mean that the sink was unavailable, and never licenses a retry.

`finishup service diagnostics --request-id req_…` reads matching owner-only records for the request
returned by check/operation status. `--correlation-id err_…` remains supported; exactly one selector
is required. Both use the same bounded, payload-free record projection and require no ledger
inspection. No new retry, lease, cancellation, network or credential authority is introduced.

### Status fault classification and project member containment (issue #840)

A status request reaches the application already validated against its frozen schema.
`INVALID_REQUEST` is therefore returned only from the explicit caller-shape sites: cursor decoding
and binding, the requested frontier, selector and view consistency, and the translation of the
caller's view, filter, and cursor position into a projection query. Any other `TypeError` or
`ValueError` raised while serving the read — including a pydantic `ValidationError` and the
`CoordinationError`/`ProjectCommandError` family, which subclass `ValueError` — is a fault in stored
state or in the service's own projection, and `application/status_faults.py` classifies it once by
the stage that raised it:

| Stage | Raised while | Public code |
|---|---|---|
| `replay` | decoding a recorded ledger, lineage manifest, host-lineage registry row, or stored operation result | `STORAGE_CORRUPT` |
| `model` | validating a projected row against its closed public wire model | `INTERNAL_ERROR` |
| `digest` | computing the task/project snapshot identity | `INTERNAL_ERROR` |
| `projection` | any other internal step (the untagged residual) | `INTERNAL_ERROR` |

All are non-retryable. Sites that already had specific fixed wording keep it (`The task ledger is
unreadable.`, `The status case is unreadable.`, `The stored operation result is invalid.`, `Host
lineage status is inconsistent.`). Each classification records one diagnostic with component
`application.status`, operation `status_<view>_<stage>_failed`, the reviewed exception-class
reason token, the structural `phase` stage, the innermost `finishup` source `origin` of the original
exception (never the stage boundary), and the request id. The public error carries that record's
correlation id and the same safe `phase`, so the daemon and MCP bridge reuse it and mint no second
`status_public_error` record; `finishup service
diagnostics --correlation-id` or `--request-id` resolves the failure. The record never contains an
exception message, a validation payload, a path, or user content. `CoordinationError` and
`ProjectCommandError` are reviewed exception-class tokens (`exception_coordination_error`,
`exception_project_command_error`, and `exception_host_lineage_registry_error`).

The project view contains faults to the member that raised them. A member that cannot be routed,
replayed, or projected contributes no lineage or receipt rows, the response `gaps` carry
`project_member_unavailable`, and a diagnostic joined by request id records the stage (or, for an
uncorrelated member public error, `status_project_member_unavailable` with its lowercase code).
One member's rows are admitted together only after both were read. Project-level detection and
coverage rows, the snapshot digest, and the page model still fail the read with a correlated
error. Member receipt rows carry the receipt's recorded `subject_frontier`; the frozen `Frontier`
wire object is normalized to a plain mapping at the strict `FrontierModel` boundary. Passing the
frozen object directly rejected every member with a recorded receipt, which failed every root's
project view as `INVALID_REQUEST` in the two-host 0.3.0 dogfood. The multi-agent MCP text summary
also carries the allowlisted gap codes within its bounded fallback so a generic client can see a
member omission without receiving private row content.


### Evidence-aware closure preparation (issues #569, #618, #657, #660, #666)

`finishup closure-prepare` is a read-only CLI support command, not a workflow operation. The current
MCP surface also exposes `closure_prepare/1.0.0` as a support tool with the same composer and
selection model. Both routes read privacy-projected `status` pages at one pinned frontier,
preserving cursor query identity.
It exposes inventory and composes one explicit selection into an existing `publish_work`, `respond`,
or `receipt` request. `finishup closure-schema` exposes the closed selection-input schema. IDs it
creates are lowercase UUID v4. Publication drafts use `dry_run=true`; preparation is non-evidential.
No selection defaults to attempted, acknowledged, resolved, or complete. Failed, partial and unknown
selected results belong to claim limitations. The existing append validator remains authoritative
for relevance, revisions, evidence admissibility and frontier conflicts. A timeout uses the emitted
operation query and the same original request identity, never a newly composed write.
`--output <path>` (issue #916) writes the exact canonical JSON line the command would print to that
file instead, owner-only, through a same-directory temporary file that is flushed, renamed into
place, and followed by a flush of the containing directory (ADR-003's durable sequence; skipped
only where the filesystem cannot open or flush a directory), and prints a bounded summary
(`preparatory_only`, absolute `output` path, `bytes`, `sha256`, `frontier`, per-view
`inventory_rows`, `operation`). An unwritable path fails as `closure_output_unwritable` with nothing
saved. A directory flush that fails after the rename fails as `closure_output_not_durable`: the new
file is in place but may not survive a crash, and no summary is printed. Each page it reads is still an ordinary privacy-projected `status` call with its
own local-disclosure receipt; the file changes where the result goes, not what was disclosed.

The MCP route sends the returned session and writer identities with an explicit selection. It is
read-only and preparation-only: it never appends, judges work, or claims completion. The bridge
checks the final host projection and JSON-RPC serialization, including Cursor's structured-content
and canonical-text copies, before returning success. Its complete response frame is bounded. A draft phase (`attempt`, `respond`, `resolve`, `claim`,
`receipt`) validates against the whole pinned inventory but echoes only the rows its selection
names, with the per-view totals and kept counts under `inventory.scope`; the `inventory` phase and
the CLI keep the complete inventory. An oversized inventory returns `LIMIT_EXCEEDED` with reason
`closure_result_too_large` and no partial success, so callers select ids from the status pages, use
a draft phase, or use the CLI `--output` fallback for a larger local inventory. Each refusal is its
own protocol reason code (`closure_attempt_selection_required`, `closure_obligation_unknown`, ...)
and its fixed remedy sentence renders on the MCP text beside the reason. The route is shared by
Codex, Claude Code, and Cursor on macOS, Linux, and WSL 2 through the local bridge. Native Windows
has no supported FinishUP MCP route; host activation and native dogfood remain separate evidence.

The obligations status row adds optional `command_attempts` (at most 64 rows). Each row contains
`requested_item_index` (canonical string 0–63), `relation`, `asserted_action_ids`, and
`observed_event_ids` (each at most 64 unique IDs). Indexes refer to the current obligation's exact
`requested_items`; no raw command or path enters structural fields. Existing `unattempted_items`
continues to describe caller-asserted accounting. Relations are:

- `matching_observed_attempt`: one distinct readable command equals the requested UTF-8 text;
- `asserted_observed_mismatch`: an assertion names the requested command, but explicitly linked
  readable observation describes a different command;
- `unknown`: observation is absent, omitted, redacted, ambiguous, or exceeds the displayed bound,
  or a linked run that does not match is the agent's own declared equivalence: a cooperative
  `command` action naming the exact value in `attempted_items` with that observed run in
  `causal_parents` (the PL6-3 link of ADR-033, which the planned-verification fact already reads as
  run and discloses as `planned_verification_agent_linked`). Such a link therefore yields
  `command_attempt_uncorroborated`, never `command_attempt_mismatch` (tb4n4, #1049).

Only service-stamped observation authorship is eligible. Explicit correlation is an action's
causal parent naming an observed action, or an obligation's resolution result naming that action.
Temporal proximity, string similarity and an observation-shaped caller payload are insufficient.
Wrappers, environment changes, whitespace changes and changed test targets are not normalized;
exact bytes are the reviewed rule, not shell equivalence. Several different linked commands are
ambiguous, even if one matches. An observed attempt never proves success. A supported obligation
revision records a replacement and rationale without retrospectively asserting the original ran.
The relation is derived at read time, so memory, SQLite, replay, CLI/MCP and receipt use one rule.
Current native profiles often omit command text: that limitation stays unknown.

Finding status `detail` appends a bounded explanation of the latest recorded check's actual failed
resolution requirements. Receipt findings/dispositions use the same explanation. Original finding
payloads, proof qualification, `resolved`, blockers and historical identity are unchanged. A
non-repeated finding with suppressed results, wrong policy/scope, weak freshness, unavailable proof,
failed AI-powered review or disqualifying gaps is not described as repaired. Local-check exceptions
do not extend to AI-powered findings. Explanation text is under existing finding-content projection.

Earlier-check receipt wording uses the recorded suffix classification: responses, finding-free
observations, or a mixture. An unavailable classification stays neutral. It names the tested
frontier without inventing finding responses. Later ingestion is not later occurrence; asynchronous
observation can advance a frontier while the old check remains attributable. A new check evaluates
later material and does not promise to remove every gap.

At completion or resolved-obligation frontiers, asserted command relations contribute
`command_attempt_mismatch` or `command_attempt_uncorroborated` to the existing local-check
case/receipt gap vector. This prevents uncorroborated accounting from becoming execution proof.
The latter means unknown observation, not non-execution. Receipt capacity computes the same union.
Hook observation records a keyed commitment (`omitted:hmac-sha256:…`) instead of command text, so a
requested command item is never byte-compared with an observed run and stays
`command_attempt_uncorroborated`. Like caller-asserted digest provenance (#912), that code is a
standing limitation no agent action changes: the work-integrity ledger rule does not make it a
`ledger_stale_or_incomplete` subject. `command_attempt_mismatch` keeps its finding.


### Observation drain control provenance

An adapter-local `ObservationControlFailure` is distinct from an `ObservationIngestResult`
returned by the service. Its `control_<reason>` token identifies a bounded control error, never
an inferred ledger refusal. Original control retryability and optional `err_` correlation remain
separate from the drain's retry/quarantine decision. All rows after a failed control attempt are
left unattempted on that connection. Invalid/oversized requests are terminal; uncertain protocol
and transport outcomes retain exact replay identity within the bounded attempt policy. Service
stage is unknown unless independently evidenced; local encode/decode stages are named explicitly.
The CLI's bounded diagnostic projection uses opaque session/source commitments and cursor
positions, with null absent correlation and explicit incomplete-history coverage.

### 0.3 integration with the 0.2.1 contracts

Released artifacts remain byte-identical. The current lineage extensions use finding and
finding-recorded `1.3.0`, check-result `1.3.0`, status-result `1.4.0`, receipt-document and
receipt-result `1.3.0`, and version-manifest `2.3.0`. Receipt documents retain optional semantic
provenance and provider usage alongside their required child-outcome section. Older receipt
documents keep their original shape when decoded and serialized.

ADR-030 recovery coverage includes every 0.3 lineage/project reason: invalid attach capabilities
require parent review, pending operations preserve their request identity, authority refusals
require explicit owner review, and terminal or invalid stored state is never automatically
replaced. These reasons have registered directives and are not coverage exemptions.


### Long semantic check waits on the 0.3 line (#746)

`external_runtime.timeout_seconds` defaults to 900 seconds and accepts 1–3600. Explicit existing
values remain effective. Primary/fallback execution deadlines are frozen before dispatch; the
lease follows their authenticated bound plus five seconds of cleanup, never the caller's wait.
A reclaimed started attempt keeps its physical provider request identity and reconciles exact
admission before dispatch. Already consumed authority is not retried. An authenticated durable
response is recovered without another provider call; missing outcome evidence stays unknown.

For checks that may use semantic review, `deadline_ms` bounds a control client's wait and initial
maintenance-gate acquisition. Once admitted, the check survives that wait or a disconnected client.
Retry the unchanged request and `request_id`: an active handler reports `OPERATION_PENDING`, while
a completed operation replays from its ledger with current client disclosure projection. Explicit
control cancellation while attached and service shutdown cancel the owned work. Local coroutine
cancellation merely stops waiting for a check. Other workflow cancellation behavior is unchanged.
The existing maintenance gate may delay other task reads while a check runs; this change supplies
pending/replay continuity, not concurrent-check scheduling. Structural progress for the running
check is readable through `status view=operation` (next section).

### Check admission stage (#838)

Every branch that refuses a new check before an operation record exists raises retryable
`OPERATION_PENDING` with a closed `reason_code`, an integer `retry_after_ms`, and the
`check_admission_same_identity` continuation, attached at construction:

| Stage | `reason_code` | `retry_after_ms` | Meaning |
| --- | --- | --- | --- |
| `acquiring` | `check_admission_in_progress` | 2000 | A live acquisition reservation already holds the exact (writer, request) key, or another invocation admitted it first. |
| `capture_handoff_pending` | `check_admission_capture_pending` | 5000 | A native capture handoff for the task is outstanding, before staging or landing during it. |
| `acquisition_contended` | `check_admission_contended` | 1000 | Concurrent motion in the case's own inputs, or a lapsed reservation, left nothing admitted. Also raised when the shared local observation store stayed contended through the bounded pre-admission loss reconciliation (issue #689); store contention during the capture-barrier reconciliation keeps that barrier's own `check_admission_capture_pending` refusal. |
| `import_pending` | `check_admission_import_pending` | 5000 | A Codex import for the session is still being published. |

Nothing is recorded under the request identity at any stage, so the exact replay after
`retry_after_ms` converges on the one operation admission eventually creates. `execute_check`
retries once inside the call for `capture_handoff_pending` (after the task-local capture preflight)
and `acquisition_contended`; it returns `acquiring` and `import_pending` directly. The daemon records
each refusal's `reason_code` in its durable public-error diagnostic, so the correlation id names the
stage. An admitted pending check with a live lease keeps the untyped `OPERATION_PENDING` and a
`found=true` operation page.

SQLite acquisition stages its resume object with the repository lock released. When only
lifecycle state that moved no ledger record changed meanwhile (another operation's lease, phase, or
AI-powered review bookkeeping), SQLite carries this acquisition's own operation row and frozen case
over that motion instead of discarding it. A change to the projection, writers, object inventory, or
this key refuses as `acquisition_contended`; a moved ledger head still returns `FRONTIER_CONFLICT`.

`status view=operation` for an `absent` page adds an optional `admission` object (status result
schema 1.4.0; omitted, never null, otherwise) while the service holds a live acquisition reservation
or a recent refusal for the exact (writer, request) key: `stage` (the closed stage above),
`refusal_count` (canonical uint; `0` only while `acquiring`), `first_observed_at`,
`last_observed_at`, `observed_at` (timestamps), `elapsed_ms` (canonical uint, from
`first_observed_at` to `observed_at`), and `retry_after_ms`. The page keeps `found=false` and
`state=absent`: replaying the exact body is still the recovery. The ledger port method is
`lookup_check_admission(writer_id, operation_id) -> CheckAdmissionRecord | None`, exposed on the
read-only runtime facade. The journal behind it is in-memory, bounded to 64 keys and 15 minutes,
never persisted, and cleared when the key is admitted; a service restart or runtime eviction forgets
it and the page reads as plainly absent again. It carries no payload and never names another
request or writer. The CLI human status rendering prints `Check admission: …` lines; the MCP text
summary adds `admission stage`, `refusals`, `elapsed ms`, and `retry after ms`.

### Observed runs in the results view (#909)

`status view=results` adds an optional `observed_run` object to a readable result row whose source
event is a service-stamped hook observation (status result schema 1.4.0; omitted, never null,
otherwise, and never on a cooperative row): `occurrence` (canonical positive uint, the 1-based
position among the task's hook-observed results in ledger order), and when known `tool_name` (the
host tool token materialization appends to the observed action's description as ` (tool <name>)`),
`command_commitment` (the installation-keyed `hmac-sha256:` command identity), and `exit_status`
(the recorded integer). All four are structural leaves visible under the default ceiling. No
command text or time finer than occurrence order is exposed, and the runner class is #910's to
add. The CLI human status rendering prints one `Results:` line per row with these facts; the MCP
structured result carries the object unchanged. Hook envelopes carry the commitment as the
`command_commitment` structural key, admitted by the unreleased control-request 2.9.0 wire with
the `^hmac-sha256:[0-9a-f]{64}$` pattern (ADR-022, #909 section).

### Structural semantic progress (#571 A2)

`status view=operation` for a pending or complete check whose AI-powered review job recorded
progress adds an optional `semantic_progress` object to the page (status result schema 1.4.0; it
is omitted, never null, otherwise). Fields: `phase` (closed: `queued`, `case_admitted`,
`runtime_starting`, `account_model_validation`, `provider_sampling`, `response_validation`,
`cleanup`, `terminal`), `attempt_ordinal` (canonical uint; `0` until the first attempt is
claimed), `queued_at`, `phase_entered_at`, `deadline_at`, `observed_at` (timestamps), `elapsed_ms`
(canonical uint), and `condition` (`active`, `overdue`, `terminal`). A non-terminal object also has
`remaining_ms`; a terminal one has `terminal_outcome` (`succeeded`, `failed`, `quarantined`) and
`terminal_reason` (a `SemanticReason`) and no `remaining_ms`. `condition` is `active` exactly when
`remaining_ms` is positive. Durations are computed by the service at `observed_at`; terminal
`elapsed_ms` is frozen at the terminal time. `deadline_at` is the frozen execution expiry.

Phases move forward only (by phase order within an attempt, then by attempt ordinal); a retry
restarts at `queued` with the next ordinal. The terminal phase is derived from the terminal
`semantic_jobs` row, so exactly one terminal state exists and survives restart. Storage is bundle
table `semantic_progress` (bundle schema 15, migration `0015`); ledger port methods are
`begin_semantic_progress(job_id, queued_at, deadline_at)` (insert once; replay is a no-op),
`advance_semantic_progress(handle, phase, observed_at) -> bool` (only the active attempt of a
leased job, only forward, never `terminal`), and `load_semantic_progress(writer_id, operation_id)`.
A check with in-check follow-up rounds (#1047) owns one job per round: the load reads the live
job, else the latest round's, the review the check records, by the `follow_up.round` its frozen
`semantic-case/2` object names (none for the check's own review); attempt count and job id order
only jobs of one round, never a later round behind an earlier one.
The read-only runtime facade exposes the load. Provider and gateway code report phases through
`finishup.observability.semantic_context.report_semantic_progress(phase)`; the service binds the
`semantic_progress_sink` context variable to exactly one claimed attempt, and a recording failure
is a bounded `semantic_progress` diagnostic that never changes the attempt.

While a service-owned check holds the maintenance and observation gates, the daemon admits
`status view=operation` reads beside it through `CheckReadWindow`; the check drains admitted
readers before releasing the gates. All other ordinary calls keep waiting on the gates. The CLI
human status rendering prints `Semantic review …` lines; the MCP text summary adds `operation
state`, `semantic phase`, `attempt`, `condition`, `elapsed ms`, and either `remaining ms` or the
terminal outcome; the terminal interface polls the page while its own check runs and offers
`/progress`. Receipts are unchanged: progress is live telemetry, not a coverage fact.


`FinalSemanticEvaluation.case_content_gaps` carries bounded native-resolution omissions from the
semantic packet into check and receipt coverage, even when the provider succeeds. Native capture
metadata is not an excerpt: without an authenticated captured group, the builder omits the excerpt
and retains `captured_object_unavailable`, including when the omission list limit is zero. The
current consent-generation fence is still checked immediately before disclosure or recovered
admission; larger review budgets do not change that authority.

ADR-030 recovery also applies to first-start contention. The three `start_*_retry_ready` reasons
carry `start_busy_same_identity` only after the catalog lease was yielded; `start_lease_pending`
carries `start_pending_same_identity`. These are the continuation tokens the 0.2.3 line released;
the 0.3 line keeps the same names and adds their nudges. Internal busy labels alone do not
establish either condition.

The native resolver reads at most the latest 256 retained envelopes from its mapped session.
`list_envelopes_for_session(workspace, session_commitment, limit=None)` and
`list_envelopes(workspace, limit=None)` preserve unbounded historical reader defaults for other
callers; a supplied integer in `1..256` bounds the SQL query before decoding and returns the window
in chronological order. Evidence outside that window cannot become an authenticated excerpt.

### Explicit Codex home in setup (issue #786)

The local MCP registration and unregistration preview commitments use revision 4 when an
explicit Codex home is selected. The commitment includes that home, and all corresponding
host subprocesses receive matching `CODEX_HOME` and `CODEX_TESTING_HOME`. Plugin activation
and MCP registration therefore address the same host configuration. This adds no control-wire
method or protocol schema; unbound legacy adapter calls retain their existing commitments.

The interactive setup wizard may refresh an MCP preview once after its own plugin activation
changes the effective entry. It displays the new target, command and digest and requires a new
confirmation. Foreign entries and subsequent drift still refuse. Noninteractive exact-preview
callers retain the stale-preview failure. The terminal UI prepares its MCP preview with the same
resolved Codex home as its activation preview.

### Cursor project registration selector compatibility (issue #786)

Project MCP registration emits the validated absolute project path for `--project-root` so both
IDE and Agent CLI clients can start the same bridge. Existing `${workspaceFolder}` entries remain
recognized for upgrade and IDE runtime verification. A registration naming another absolute
project is foreign. In default desktop mode the selector must match the native client roots/list inventory and
the exact owned project registration; no CWD or caller-authority fallback is added.

### Selected observations across local control (issue #786)

Control request 2.6.1 carries the existing ADR-029 selection route identifiers, authority
generation, subject-state digest, and protected-read reference. Selection route fields are
all present or all absent. Routine summaries use the existing closed summary schema; individual
observations remain closed to unknown fields. Domain and service route/authority validation
remain mandatory. Released request 2.6.0 bytes and the hello contract remain unchanged. The 0.3
line's request contracts (`2.7.0`, `2.8.0`, `2.9.0`) derive from `2.6.1` and carry the same fields
and summary branch, so an envelope the 0.2.3 service admits is admitted unchanged after upgrade.

Routine-read classification persists its proven success bit when the native outcome was nested.
Summary construction still revalidates that bit. A legacy buffered group that cannot prove a
summary is delivered as its original individual observations, in source order, without inventing
success or dropping accepted records. One invalid summary no longer blocks later hook ingestion.
On the 0.3 line each such record additionally carries the `routine_summary_invalid` coverage gap
and the lane records one bounded summary refusal (#764); the record itself is otherwise unchanged.

### Explicit Cursor Agent CLI project binding (issue #786)

The maintainer approved this separate CLI binding design on 2026-09-19 after the native Agent
CLI connected but could not supply MCP roots/list. `integrate cursor project-mcp` accepts
`--project-binding registered-project`. The local preview names the project, launcher, instance,
route and binding mode; its digest binds all of them. Omission preserves an owned entry's mode,
or uses `mcp-roots` for a new entry. Explicit `mcp-roots` reverses the CLI selection.

The rendered bridge command carries the same mode. It requires an absolute project and exact
owned registration with that flag, revalidates the symlink-free project/configuration identities,
canonical repository root and directory identity before every workflow operation, and retires on
any drift. It binds only the configured project; CWD, hook payloads, workflow arguments and MCP
clientInfo cannot select or switch it. There is no automatic fallback when desktop roots fail.
No content-capture permission, privacy grant, egress ceiling or service-instance boundary changes.
Removal is the existing accepted project-registration removal lifecycle.

### Bounded first-start recovery (0.2.3, issue #786)

A same-bundle session rebind waits at most five seconds for existing runtime users to retire.
At most 64 foreground rebind waiters are admitted per cached bundle on the 0.2 line; on the 0.3
line that bound is the runtime policy's `max_pending_leases_per_task` (default 64), and the
waiting start must also match the cached entry's scope. Waiting releases the cache
lock, protects the entry from eviction, and blocks new old-session leases. A definitively returned
retryable busy attempt yields only its fenced pending start-catalog lease; durable identity, phase
and milestones remain. Cancellation and ambiguous response loss do not yield that lease.

ADR-030 continuation `start_busy_same_identity` names exact once-only replay after a successful
lease yield; `start_pending_same_identity` names a live lease and the bounded 60-second wait before
exact replay. Runtime/catalog producer reasons alone never imply a released start reservation.

## Native required-startup gate (issue #692)

`render_claude_code_plugin` and native `render_cursor_plugin` accept `startup_mode=optional|required`.
The default is optional. Lifecycle commands expose `--startup-mode`; omitting it preserves the
marker-verified installed mode through `installed_claude_startup_mode` / `installed_cursor_startup_mode`.
Status reports `startup_mode` and nullable `installed_startup_mode`. Common setup preserves that mode.
The artifact inventory/digest owns the hook bytes; no public ledger/MCP wire schema changes.

`hooks startup-context --host claude|cursor` reads only bounded packaged guidance and emits native
SessionStart context. `hooks startup-gate --host ... --event ...` owns the separate required tool gate.
Private `yoetz.startup-gate/1` state in `startup-gates/` uses owner-only files and a nonblocking
per-host/session/workspace lock, generated generations, route ids, effective plan refs, accepted
obligation refs and pending request refs/generations. Prose and host payloads are not retained.
A successful host response only nominates readiness; `startup_gate_probe` reads live repository-bound
compact status to confirm the route, plan and readable scope. An independent child deadline bounds
service contention; no capture/drain locks or direct ledger reads are used.

Claude returns deny or abstains. Cursor generic preToolUse returns allow/deny while the separate
server-qualified MCP hook returns ask/deny, preserving ADR-018. Cursor permission hooks request
failClosed; Claude command timeouts remain host-fail-open. No owner approval is inferred.
See [required startup](runbooks/required-startup.md) for scope/recovery, lifecycle and proof limits.

### Setup next-step and Codex inspection targeting (#737)

`setup status --next --operation local|review|connection` emits `yoetz.setup-readiness/1`
(`integrations/setup-readiness-1.0.0.schema.json`). It carries the selected project, inspected host
configuration root, bounded reason, read-only prerequisite facts and one quoted `next_command`
(or null when no setup prerequisite is missing). `connection_observed` is always false. Local and
review operations evaluate service/vault/repository prerequisites; review additionally requires a
provider binding and review permission. Connection-only evaluates the common host plan without
requiring service or provider login. No native session or provider dispatch is inferred.

Codex plugin/MCP/provider status gain the additive local inspection field `inspected_codex_home`.
Their existing schema tokens remain unchanged; this field is not a service-wire or ledger field.
All accept `--codex-home`, with explicit flag > `CODEX_HOME` > `CODEX_TESTING_HOME` > `~/.codex`
precedence; every invoked Codex subprocess receives both variables bound to the selection.
Explicit MCP previews bind the same home through registration, removal and reconnection.
Plugin removal retains its explicit-home requirement. Setup status accepts Codex aliases for the
common host target. Activation refusals expose `next_command` with the exact executable and home;
that command obtains its own activation preview and requires its existing independent approval.

Missing provider binding during privacy recipe preparation maps only the exact internal
`privacy_setup_provider_binding_required` reason to public `provider_binding_required`.
Other malformed bindings remain `grant_binding_invalid`; exception text never enters output.

`setup vault` is a human-terminal-only composition of the existing initialization/unlock
ceremonies. It stops before provider selection and policy changes. `setup status --next` selects
it for an uninitialized vault; the common host connection command alone never stands in for
vault initialization. Continuations retain module-invocation interpreter spelling so a symlinked
virtual-environment Python does not lose its runtime pin.

### Completion claim scope diagnostics (issue #679)

`kernel/completion_scope.py` owns the comparison between each readable effective completion
claim and `current_plan_scope`. `completion_claim_outside_plan` and
`completion_plan_not_claimed` are fixed coverage codes carried by publication previews/results,
status, checks, and receipts. There are at most two case gaps regardless of relation count.
Status readiness uses its existing `coverage_gaps_declared` condition and classifies both codes
as agent-actionable in its checklist (ADR-032); declared/open obligation counts stay plan-derived. Receipt gap details contain at most 16 ID-pair examples plus full
relation counts, with an explicit omission marker; default privacy projection still applies.
Partial claims are accepted. Material/superseded claims are excluded, and unavailable input is
not an empty scope. Multiple partial claims are compared independently; older effective claims
are compared to the current plan until explicitly superseded. A later plan revision that waives a
previously claimed obligation changes the current plan but does not rewrite that claim, so the
outside-plan code remains expected until the claim is superseded. See ADR-019 for repair semantics.

### Command-gap independence for repaired action findings (issue #682)

Maintainer acknowledgement: [issue #682](https://github.com/TheGaySupreme123/finishup/issues/682#issuecomment-5761527250).
`finding_resolution` admits a narrow exception for a deterministic `action_without_result`
finding with readable original proof, one exact action-event subject, explicit readable obligation
links, and an accepted linked result present at the checked frontier. It bounds the possible
owners of `command_attempt_uncorroborated` and `command_attempt_mismatch` using all selected,
plan-declared obligations that request commands. The relation includes both an action's direct
`obligation_refs` and a selected obligation's `resolution_evidence_refs → result → action` link.
Only a proven disjoint action relation may ignore those codes for that finding's absence proof. The
codes remain on the check and receipt.

This is deliberately conservative: the partition includes selected command obligations even when
a command was observed matching. An action sharing such an obligation still requires the command
coverage to be repaired; an absent, ambiguous, redacted, or unbound relation never qualifies.
A later material projection row cannot establish proof for an earlier checked frontier. The
check's own finding suffix is immaterial to action/result/plan inputs. Explanations reconstruct
the projection immediately before the candidate check when needed; the same per-row frontier
guards identify overlapping obligation IDs (bounded to 16) or that independence remains unproven.
Once independence is proven, the command codes are removed
before freshness is evaluated, so the existing closed host-observation exception may also admit a
`redacted_gap` check when all remaining gaps are tolerated host/evidence limits; projection
redactions and unknown relations still block. All ordinary scope, policy, suppression, refiring,
freshness and semantic requirements continue to apply.

**Content-capture gaps (tb4n5 follow-up, owner decision 2026-10-13: "under capture gaps").** For
the same finding, `_action_result_link_proven` (the tested state holds the readable subject action
and a readable `result_recorded` whose `action_id` names it, both no later than the checked
frontier) makes `truncated_payload` and `content_capture_unavailable` (`_ACTION_LINK_TOLERATED_GAPS`)
stop vetoing the absence proof, whatever obligations the action names; the codes remain on the check
and receipt. The command codes keep the partition above (the owner may widen this later), so tb4n5
formal S, an unbound action under `command_attempt_mismatch`, still reads
`command_relation_independence_unproven`. Explanations also replay the pre-check projection when the
check carries one of the two capture codes.

**Same-batch siblings (tb4n5 follow-up).** The rule's "subsequent unrelated work" never includes a
sibling action the same cooperative `publish_work` batch recorded: 8 of 15 tb4n5 findings fired only
on such a sibling. The frozen case carries the batches as `DeterministicCase.action_batches`
(groups of two or more agent-published `action_recorded` events of one operation id on a
`cooperative_mcp` or `local_cli` channel; never an observation, import or engine row), and its JSON
gains the key `action_batches` only when such a group exists, so every other case keeps its exact
bytes. The work-integrity pack stays `0.3.0` (unreleased, amended in place).

The reducer supplies the same projection context to the qualification predicate used by status
and receipts. No new event schema, persisted proof metadata, or command execution claim is added.
Historical event bytes remain intact; rebuilding a projection applies this bounded derivation to
its accepted history. A held old check is still invalidated by a later response to a finding that
check did not return, except an unscored acknowledgement of an observation-authored, non-actionable
finding (#911). Resolved history does not remove receipt coverage limitations.

`semantic_packet_insufficient` is a coverage gap on a committed check whose valid provider
judgment is `insufficient_packet`. It reports unassessable content without adding a defect
finding, and must remain visible in CLI, MCP and receipt coverage. A succeeded attempt with this
gap is not a complete review and cannot prove absence of a prior semantic issue.


Semantic finding resolution compares the later completed review's native capture gaps against
the readable original finding's capture baseline (ADR-006, issue #884). Only the closed existing
baseline is tolerated; it does not remove any receipt coverage gap. `insufficient_packet` cannot
resolve a prior semantic finding. Response disposition and limitation acceptance are not proofs.
Semantic findings carry their review's closed capture limits in their own coverage, and resolve only
after a readable material change recorded after the finding (`no_material_change_since_finding`
otherwise). No ADR-031 check-time change code is a capture baseline. A semantic repair check's
`check_time_change_*` codes are tolerated for a finding only by the shown-file rule
(`check_change_limits_tolerated`, `CheckChangeShownFiles.covers`): every file the raising reviews
(R) need whole is in the repair check's `fully_shown`, and every file R saw in part (`shown_bytes`
n, `redactions` k, `view_commitment` v) is in the repair's `fully_shown` or has a repair partial
entry q with `q.view_commitment == v` (maintainer decision 2026-09-30, R945-02). A raising partial
entry without `view_commitment` (written before the field existed) falls back to (`q.shown_bytes >=
n` or `q.section_admitted`) and (`q.redactions <= k` or `q.clean_bytes >= n`);
`check_change_resolution_unverified(record)` is true for a resolution that tolerated check-time
limits while R held such an entry, and the receipt then adds the gap
`check_time_change_resolution_unverified` once, with the task-wide marker
`check_time_change_resolution_unverified` however many findings it covers (receipts hold at most 64
gaps and fail to build past that, so a per-finding marker could make the receipt unavailable);
`unverified_resolution_finding_ids(projection, resolved_ids)` lists them, and the gap's `detail` and
the limitations body carry the fixed sentence plus up to 16 affected finding ids and a count of the
rest. As a receipt gap it lowers ledger freshness from `current` to `partial`, which turns a
`no_unresolved_deterministic_findings` conclusion into `insufficient_coverage`; that is deliberate,
and only tasks carrying check records from 0.3 development builds of ADR-031 can reach it. A repair
entry without `view_commitment` never matches a raising entry that has one. The repair record may be
incomplete; an empty R is always tolerated and an unknown R never. `FindingProjectionRecord` carries
the replay-derived `check_change_raising_check_event_ids` (every contributing check, in fold order),
`check_change_raised_files` (R as a complete `CheckChangeShownFiles`; `None` while unknown) and
`resolution_depends_on_check_event_ids` (the contributors, when a resolution needed that tolerance).
A check contributes to each semantic finding it returns when it recorded a conclusion or is the
finding's raising check (same subject frontier and AI-powered review attempt). A contribution is the
check's complete record, unknown for an incomplete record or carried-part codes without one, and
empty otherwise; contributions merge with `CheckChangeShownFiles.merged` (union of whole files; a
file seen in part through one view keeps it, through two different views (or one legacy and one
committed) it must be seen whole, and two legacy views keep the larger length and fewer redactions;
unknown past `MAX_CHECK_CHANGE_RAISED_FILES` = 1024 files or when either side is unknown); past
`MAX_CHECK_CHANGE_RAISING_CHECKS` = 64 contributors R is unknown. Redacting any contributor sets R
unknown and reopens a resolution that depended on it; all three fields are emitted in projection
snapshots only when set.

Issue #904 adds the reduced reference scope to that baseline (ADR-006). The check stamps
`semantic_reference_scope_reduced` onto the semantic findings its reduced-scope review raised. For
a finding recorded before that stamp, the reducer reads the raising check's recorded coverage
(`reduced_scope_raising_check_event_id`) and never rewrites the finding. A finding raised under a
gap outside the baseline set gets a readable baseline on the first later check carrying none of
those gaps; while one is present it keeps blocking. Resolution classifies selection codes
(`semantic_reference_scope_reduced`, `content_unselected`) apart from capture-failure codes
(`truncated_payload`, `event_payload_unavailable`, `redacted_event`,
`redacted_object`), which neither proof class tolerates and no baseline absorbs. Since issue #982
`content_redacted` is a host-observation limit instead (it never vetoes local proof and is an
AI-powered-proof baseline), `semantic_review_item_withheld` is semantic-only and a baseline, and
`semantic_review_value_redacted` and `semantic_review_credential_heuristic_disabled` are tolerated
by both proof classes. `truncated_payload`
keeps blocking until its source is settled. Coverage wording and every receipt gap are unchanged.

The baseline tolerates `semantic_reference_scope_reduced` for a semantic finding only when the
later check shows that its reduced review sent the finding's material (PR930-F1). A completed
reduced review records `semantic_included_refs` on the check: the frontier references the exact
prepared packet carried, read after envelope bounding and privacy minimization. The selected
attempt's durable response carries the same set, so recovery and resume record it too. A reference
counts when it is the `source_ref` of a carried content item, or a part of a carried multi-part
captured evidence excerpt (an `evd_` reference linked to the lead excerpt that combines its bytes).
An action, result, evidence, claim or obligation record also counts when the history item of the
event that recorded it was carried with its recorded payload, which is how records travel when
recorded history is available (#947 added actions, claims and obligations; a superseded claim
travels only this way). An earlier finding counts when its structural prior-finding row was carried;
its prose rows alone do not, and a `not_recorded` omission on its prose does not remove it.
The payload's presence is read from the item's own content, never from omission rows, which the
selection cap may drop. That does not apply when an omission row names the record for a reason
other than `not_recorded` (for a record without a captured object, nothing more readable than the
payload exists, as for digest-only evidence). Evidence with a captured object never counts through
its recording event: it counts only when its own excerpt was carried, so bytes that were never
resolved or were left out are never credited, whatever omission rows survive. Mentions
in other items, other typed links, the citable-reference list and omission rows do not count, and
a reference named by any omission row is excluded even when a structural item for it survived
(except an earlier finding, above). The record holds typed ledger references only, ASCII-sorted, 1
to 576 of them: one source per case item (256), the combined captured parts (64), and one record per
carried history event. The event that recorded a carried record is never written into it;
resolution derives that alias from the pre-check projection (#947), so the bound holds. It appears
only on `check_recorded` 1.3.0 beside `semantic_conclusion` and the
`semantic_reference_scope_reduced` coverage code. The record must contain the finding's own
prior-finding row (its `fnd_` id) and account for every finding subject (#947). A subject is
accounted when the record holds it or the record of the content it recorded, when it is a claim
(or the event that recorded one) that a claim in the record superseded directly or through a chain
of corrections, or when it is the recording event of an action, result or evidence record older
than every history row the record holds and among the first eight subjects, which the prior-finding
row lists (`MAX_PRIOR_FINDING_LISTED_REFS`). The record must also contain every repair reference
linked by the finding's latest readable response. Cited evidence counts, and so does the evidence of
a cited result, or the result itself when it cites no evidence. The record must also contain at
least one material change after the finding, named by its logical row or by its source event.
Otherwise the code stays a blocker and the explanation adds
`finding_material_outside_reduced_review_scope`. An unreadable response or linked row cannot be
shown to have been sent. When nothing changed materially, only `no_material_change_since_finding` is
named. The response event itself is not required; an acknowledgement is not repair evidence. A
result citing no evidence travels only through its recording event in the recent history window, so
citing the repair's evidence, which rechecks select first, keeps a long session's repair in view.
The rule reads no new field, so it applies on replay to every recorded reduced check. The findings
status view and the receipt explain an open finding against the newest later check that could
resolve it (its policy completed over a scope covering the subject and, for an AI-powered finding, a
completed review), name a newer check that could not, and otherwise fall back to the newest later
check.

When a completed reduced review's sent set cannot be recorded, the check records no field and
carries the coverage gap `semantic_included_refs_not_recorded`. Causes: the prepared document is
not a readable review packet, the packet carried no frontier content item, the set exceeds the
bound, or the selected result was recovered from a durable response written before this record
existed. A valid sent set stays within the bound by construction. Status and every receipt
rendering show the gap like any other. It limits the reduced review only: local proof tolerates
it, and it blocks AI-powered proof. The continuation is bounded:
make sure the repair evidence is recorded and cited by the response, then run one new check, whose
new review attempt records what it sent. If that check carries the code again, stop rechecking,
leave the finding current, and disclose the limitation in the receipt. ADR-006 (#904) holds the
truth table.


`check_recorded` version `1.3.0` adds required `semantic_conclusion` on succeeded attempts. The
closed values are `no_material_discrepancy`, `challenges_returned`, and `insufficient_packet`.
Versions 1.0–1.2 keep their frozen payload shapes and read without a recorded conclusion. Only an
explicitly assessable conclusion enables capture-baseline resolution. An unassessable conclusion
blocks semantic absence proof even if a producer omitted its coverage-gap marker. Failed and
local-only attempts retain their existing version. Version `1.3.0` (unreleased, so edited in place)
also admits optional `check_change_files`, `{"complete": bool, "fully_shown": [commitment],
"partially_shown": [{"clean_bytes", "commitment", "redactions", "section_admitted", "shown_bytes",
"view_commitment"?}]}`, only beside a conclusion (`view_commitment` is optional only so a record
written before it existed still decodes; every new record carries it): disjoint `hmac-sha256`
commitments sorted by commitment, counts in `0..262144` with `clean_bytes <= shown_bytes`, at most
128 files in all; `complete` false means more files were shown and the record holds the first 128 in
change order (ADR-031 decision 9). Rows written by the branch-only builds of this field before its
final shape no longer decode. It also admits optional
`semantic_included_refs` (#904): the frontier references the reduced review's sent packet carried,
at most 576. It is present only with `semantic_conclusion` and the
`semantic_reference_scope_reduced` coverage code. It is omitted on unreduced reviews, so their
bytes are unchanged. The owning schema generator and
`fixtures/canonical/check-conclusion-1.3.0.case.json` lock the new and legacy bytes.

### Review packet selection and named missing items (issue #907, Phase 1a)

The provider review packet is `yoetz.review-packet-case/2`. Every `items[]` row carries
`occurred_order` (the source's ledger ingestion order) and rows are listed in case order (section,
then recording order), never by opaque item id. An excerpt may carry `latest_for` (`path`: the
newest applied or unconfirmed captured edit of each changed path; `command`: the newest recorded
output of a command identity) or `superseded_by` (the source refs of the newer edit or run). The
marks describe recording order only; they never claim what the working tree now contains.
`review_packet` keeps its `outbound-case` 1.1.0 shape; `schemas/privacy/` is unchanged.

The successful provider path records only the `provider_bound` `review_input_manifest`. A
`composed` manifest is the pre-admission selection and must not be rendered as provider evidence.
If a provider call succeeds but that exact manifest cannot be retained, the check keeps the
provider result and records one closed provenance gap: `semantic_provider_input_manifest_missing`,
`semantic_provider_input_manifest_invalid`, `semantic_provider_input_manifest_parse_failed`,
`semantic_provider_input_manifest_mismatch`, or
`semantic_provider_input_manifest_recovery_failed`. These codes describe evidence loss; they do
not turn a successful provider call into a provider failure or a clean complete review. Durable
response recovery carries the same bounded reason, and an older response without the field is
read as an unproven provider binding.

Reviewer snippets are fenced against the exact safe text rows in that provider-bound packet after
privacy transformation and budget selection. The text index is ephemeral and is never placed in a
check result, receipt, or durable response. The packet's `citable_refs` names only refs whose
content it carries (a content row's `source_ref` or `linked_subject_refs`) and this check's local
findings whose assessment row survived; the text index holds exactly those refs (an assessment row
is indexed as sent text for its finding), so a reviewer following the contract never cites an
unsent ref (issue #976). A quote is proved when it is an exact substring of a cited row's sent
text, or matches it after one shared normalization (typographic quotes and dashes folded to ASCII,
whitespace runs collapsed; a JSON row is also searched through its decoded strings; a redaction
placeholder matches only FinishUP's own `[REDACTED]` marker at that position). Case, letters and
digits are never changed, compatibility forms are not folded, and nothing may be elided; a
placeholder-only quote, or a span with control or format characters, proves nothing. The recorded
snippet is the verbatim span the quote matched: sent text, or for a JSON row the decoded string the
reviewer read. If a response is recovered without the index,
nothing is proven sent: quote-bearing challenges become `ref_not_carried` advisory concerns and
verification rows with quotes are dropped.

Excerpt selection stays inside the approved count and byte budget. Reserved room comes first: the
current diff, then the latest output per identified verification command (with the last failure
beside a later pass, and the reserved run's exact command when the selection carries command
text), then prior-finding repair evidence (#898), then older hunks of a changed path (a captured
edit is a hunk, so an older one may still be current code; it is marked `superseded_by`);
everything else follows by recency, then link class, and superseded runs come last. A run is one
recorded result, so a run's output and its failure summary are never marked as superseding each
other. A command identity is the digest of the run key of
the command a recorded result answers (its text with whitespace collapsed, or a hook run's keyed
command identity; a hook run without one, `omitted:structural`, identifies nothing). When the
command ran again later and that newest run left no excerpt the packet can carry, every older output
of it is marked `superseded_by` the newer result and ranked with superseded runs; two `artifact`
evidence rows naming the same plain path are one output, and the older is marked `superseded_by` the
newer (#1045). Read-only task input files (`task-input-NN`, `repository_excerpt`, ADR-031 #1045
and #1082 amendments) are admitted first, ahead of the check-time change, within a quarter of the
packet's excerpt budget and within `_first_task_input_slots` (the recipe's count less the change's
reservation, at most one per part, and two slots per decisive verification run: the latest, or
each run a follow-up asked for); one that does not fit is skipped and backfills last. `TaskInputFile.origin`
(`task`, `verification`, `outside_workspace`) and `TaskInputFile.summary` choose the label; both are
optional stored keys written only when not the default. Candidates come from `review_input_paths`
(statement words, `role: input` files, then named absolute directories) with the newest
verification oracle (`verification_input_paths`) in fourth place; a binary input (a signature
`declared_binary_format` recognizes, or a NUL in its first 8000 bytes) becomes
`summarize_task_input` text, stored `redacted` when it quoted a scanned value only as a marker,
and a large untracked one keeps its two ends, each cut moved clear of a recognized credential
(`finishup.adapters.task_input_read`). A captured edit of only files whose every
section the admitted change parts carry is marked `superseded_by: ["check-time-change"]` and ranked
as an older hunk (#1082). An agent's digest-only evidence row whose SHA-256 equals an admitted
capture's content digest, and that records the same verification run (equal
`verification_identity` and `verification_run`), adds its ref and links to that capture's excerpt
(`_alias_digest_only_rows`); a row bound to no run or to another run is never aliased (PR #1086
review R1-01), and the row keeps its own excerpt. A resolved obligation's item also carries `resolved_basis`: `claimed_result_refs`,
`latest_observed_verification_refs` (the newest hook-captured verification of those results,
at most four) and `missing_input` (`claimed_result` and/or `verification_output` when that
piece is not readable). The criterion is the obligation text itself. The basis adds no command
text, summary, or path, and no category the obligation item did not already use (issue #1079).
The obligations section begins with one `declared-deliverables` item
(`yoetz.declared-deliverables/1`, obligation text): each declared `role: output` item with its
obligation, index, kind, value and `in_check_time_change` (`added`, `modified`, `deleted`,
`renamed`, `changed`, `not_changed`, `outside_repository`, `unknown`), and `facts`, the check's
closed delivered-set codes such as `deliverable_references_undeclared_file`. The task statement
(#908) is its own section and never competes for an excerpt slot. Each excerpt holds one recorded
source or one part of one capture. Excerpts honour the approved `max_excerpt_bytes` instead of the
4 KiB structural item clip; long output keeps its head and tail with a marked elision; an
oversized plan, obligation, claim or decision payload has its longest prose clipped the same way
and falls back to `yoetz.bounded-content-omission/1` only when clipping cannot fit.
A clipped structural payload is named by `semantic_case_content_over_item_limit`; an excerpt
clipped at `max_excerpt_bytes` is named by `truncated_payload`. The builder measures the exact
prepared document and drops lowest-ranked excerpts (`not_selected`, `content_unselected`) to stay
below the effective channel ceiling: the schema maximum, narrowed by the effective policy's own
`llm_inference` `max_bytes` and `max_tokens` (at the gateway's four bytes per token), so a narrower
owner ceiling drops excerpts instead of denying the whole review. Every candidate the excerpt count
or byte budget cuts (ledger evidence, exact commands and failed-result summaries as well as captured
content; all compete in one admission loop) is a `not_selected` omission and adds
`content_unselected`; past the omission list's own cap the gap is the trace. Items the
selection's relevance rule excludes (Assisted's `linked_subjects_only`) are policy exclusions, not
budget cuts: their `not_selected` omission rows state them and they add no gap.

`provider-judgment` 1.1.0 requires `missing_for_assessment` (1–8 items of `kind`, up to four
`target_refs` from `citable_refs`, and a short `reason`) on `insufficient_packet` and forbids it
elsewhere; 1.0.0 stays frozen. Like the rulings, the list is read backward: a reply that omits it
(or sends it empty) beside another conclusion reads as absent, and an `insufficient_packet` that
names nothing (a local model or prompt-only host) keeps its conclusion and rulings with no items and
discloses `semantic_missing_items_rejected`. A malformed item still rejects the reply. The check
fence trims targets to the packet's `citable_refs`, as it trims a ruling's cited refs, dropping an
item left with none (`semantic_missing_items_rejected`), and drops an item whose earlier request was
answered by material recorded since unless the reviewer cites that material
(`semantic_missing_already_supplied`). If the same target is named again without related agent
publication, the item remains actionable and adds `semantic_missing_non_convergent`; a genuinely
new target is evaluated independently. "Answered" is judged per named target: a repeat is dropped
only when the earlier request named every one of its targets and each has new agent-published
material directly tied to it. For an action, result or evidence target that is a result of the named
action or of another run of the same command (text compared with whitespace collapsed; a hook run's
`omitted:<digest>` matches only the same digest, `omitted:structural` nothing) and the new evidence
that result cites; content `git diff` runs and new evidence at the target's paths, when together
they cover every path the target records (a diff of one file never answers an edit of two); or new
evidence whose `reference` is the target's id, which always ties it. A target's paths are the
workspace-relative paths a hook-captured edit's authenticated bytes record, the pathspecs of a `git
diff` behind it, and its own `reference` unless a command other than `git diff` wrote it (an
artifact such as `reports/junit.xml` is answered only through that command's runs). Paths compare
normalized but exact: `./`, `.` segments, repeated and trailing slashes are dropped, case is kept,
`..` is not resolved. An absolute path counts only inside the workspace root the session opened with
(the root as given and as `realpath` resolves it; the agent's path is compared lexically and never
resolved), as the path relative to it; outside it, or when the root is unknown, it matches nothing,
and a basename alone never matches. A single segment without a slash (`Makefile`, `.gitignore`, but
also `stdout`) is a path only when the other side is certainly one (`./Makefile`, a captured path, a
`git diff` argument). A content `git diff` is `git [--no-pager] [-C <workspace root>] diff [options]
[revisions] [--] [paths]`; no path (or `.`) is the whole tree, and a directory covers the files
beneath it; summary forms (`--stat`, `--name-only`, `--numstat` and the like) and `-C` naming
another directory do not count. The workspace root and the captured paths are compared in process
and never recorded, logged or sent. Re-citing the old target, a shared obligation, or a record that
only cites other new material ties nothing. A claim is answered by material tied to what it cites,
and by a correction that supersedes or disputes it together with the new material the correction
cites when that material is tied to the claim's support, or when the claim cited nothing FinishUP can
relate (the request was for the claim itself). A finding is answered by a response to it and what
that cites, a plan by the version superseding it, an obligation by new actions, results, claims and
plans naming it. A record related to the target only through another path, run or claim therefore
never answers it. Only an item with no target is matched by record family alone, and
`supplied_since` lists refs on the same rule. Only agent-published material answers a request, never
hook-captured tool output: authorship is the service-stamped envelope fact, carried on the frozen
case as `observation_event_ids`, the observation-authored events recorded after the request, emitted
only when non-empty so other cases keep their bytes; and a result answers `verification_output` only
when it carries output (linked evidence or a summary). The next packet carries that published
summary as an evidence excerpt when the selection already allows an evidence or test excerpt,
ranked after the current diff and inside the existing excerpt budgets; a summary that does not
fit is omitted and named. A command the request does not name is not carried this way, and
Private sends nothing. Public check, MCP, terminal and receipt text names, per kind, the one
record to publish. FinishUP classifies each kept item as
`agent_suppliable`, `structurally_unavailable_on_this_host` (a kind the effective review selection
or channel can never carry, or a redacted target) or a FinishUP limit (`yoetz_limit_unsupported_data_type`,
`yoetz_limit_packet_room`; ADR-006, issue #983), adding `semantic_missing_agent_suppliable`,
`semantic_missing_structurally_unavailable` or `semantic_missing_yoetz_limit`. Only
`agent_suppliable` is ever agent work. After two `insufficient_packet` reviews in a row with no edit
since, or four since the task's last assessed review, checks other than `semantic_required` skip the AI-powered review and disclose the standing gap
`semantic_review_skipped_insufficient_packet` (`kernel/review_round.py`). These are check limitations, never findings, and weigh
on finding resolution exactly like the `semantic_packet_insufficient` they ride beside: a local
issue is still proven absent, and a `fixed` ruling (#905) still resolves its own finding.

Image and binary files in the packet (ADR-006, issues #983, #1004; no new wire field). No bytes or
pixels of such a file ever leave the machine. An evidence row that records one (a hook-observed
image, or a row whose `reference` names an unsupported file type and records the file itself) is
carried as an `evidence_excerpt` that begins `[FinishUP: the agent referenced an image or binary file
at <path> (evidence <evd>); it was not sent and its content is not assessable from this packet]`
(an observed image has no path: `[FinishUP: an image was observed (evidence <evd>); it was not sent
and its content is not assessable from this packet]`). The path keeps only ASCII letters, digits,
space and `._/+@~=,-` (others become `_`) and at most 160 characters. Agent-authored excerpt text
never begins a line like a label: such a line is prefixed `(agent text) `, and the reviewer
trusts a label only as an excerpt's first line naming that excerpt's own `source_ref`. The newest 16 (`MAX_BINARY_NOTICES` in
`application.semantic_case`) are reserved excerpt room. A row whose `reference` names such a file
and which carries text (`command_output`, `test_result`, `other` or captured output) is labelled
`[FinishUP: agent-rendered text of <path> (evidence <evd>); the binary file itself is not sent]`. Both
appear in the manifest's `caller_evidence` section. The predicates are
`application.missing_for_assessment.unsupported_data_type(name)` and
`observed_image_evidence(payload)`. A rendering recorded after a missing-item request for the
binary's row answers it under the path rule above.

The unreleased `check_recorded` 1.3.0 is extended in place with the optional
`missing_for_assessment` (kind, target refs, availability; no reviewer prose; 1–8 items, only beside
`insufficient_packet`), present only when at least one item survives, beside issue #905's optional
`prior_finding_verdicts`; a check with neither keeps its bytes, and 1.0–1.2 keep their shapes.
`provider-judgment` 1.1.0 likewise carries both lists. The projection keeps the latest request as
`pending_missing_for_assessment` until an assessed review clears it (an `insufficient_packet` that
recorded no item leaves it standing); snapshots omit the key when absent. The next packet carries it
as the timeline item `prior-missing-for-assessment` with `supplied_since` refs. The check result's
optional `missing_for_assessment` (check-result 1.3.0, unreleased, additive) and the MCP and CLI
check text list each item and its availability; status, TUI and receipts carry the gap codes. The
reviewer's reason stays in the encrypted durable semantic response object.

In-check follow-up (issue #1047, ADR-006). While a review concludes `insufficient_packet` and names
a `current_diff_for_path`, `verification_output` or `command_identity` item that the fence kept as
`agent_suppliable` or `yoetz_limit_packet_room` and whose targets FinishUP holds rows for
(`application.missing_for_assessment.plan_review_follow_up`; `FOLLOW_UP_KINDS`;
`ReviewFollowUp`), the same `check` rebuilds the case with those rows' excerpts ranked first within
`follow_up_byte_budget` (half the approved `max_total_excerpt_bytes`, shared by every round) and
asks again, at most `MAX_REVIEW_FOLLOW_UP_ROUNDS` (3) times and only when the rebuilt packet carries
a requested excerpt no earlier packet of the check carried. A target resolves to itself, the rows
an `evt_` target recorded, and for a run its results, its action and the evidence they cite;
redacted rows never count. A `verification_output` item may also name hook-captured output of the
newest run of each command those targets name (`observed_command_output_refs`). Selection admits
those bytes only when the recipe would already send a repository excerpt, as category
`repository_excerpt` and source kind `command`, labelled observed rather than agent-published, and
only inside the existing excerpt budget. The command must already class as test, build, lint, or
typecheck. An environment dump, a credential-named path, a path outside the workspace, or a path
the frozen check-time change refused is withheld whole (`withheld_by_policy`). The check-time
disclosure scan, including a private-key body or END line, drops the whole item
(`redacted_never_send` or `never_send_heuristic`); a partly redacted capture is not sent. A
gitignored path the change did not list is not re-probed. A channel that withholds
`repository_excerpt` drops them. Private sends nothing. Output of a command the targets do not
name is not included. A readable command action that no readable result cites occupies the
command, so a tombstoned newest result is not replaced by an older capture. A command recorded
as `omitted:structural` has no run key and is not auto-supplied. The capture still does
not count as the agent having supplied the item. Each round goes through the same privacy path,
is its own egress, and is its own durable semantic job keyed by its case digest (`LedgerPort.load_semantic_job(writer,
operation, case_digest=None)`); its `semantic-case/2` object names the base job
(`follow_up.base_case_digest`, `round`) and keeps the base job's endpoint, retries and budget
profile with its own deadline. The check records the last round: a failed round is recorded as a
failed first review is, and a round that sends nothing leaves the previous review standing. The
review input manifest gains the optional `follow_up_round` (1–3; in place on the unreleased
check-recorded and check-result 1.3.0/1.4.0, status-result 1.4.0 and outbound-case 1.2.0); in a
follow-up packet its `missing_inputs` list the in-check request, `supplied` with the added excerpt
sources (provider-bound: only excerpts that crossed the boundary) or `pending`. The evaluation's
in-process `case_excerpt_refs` (`application.semantic_case.sent_excerpt_content_refs`: what the
exact sent packet's excerpts held, read from its provider-bound manifest, a captured group's
`evd_` parts included, which its linked references keep ahead of linking events and claims within
their 16-ref bound; `None` when unknown) lets the check tell what was shown and what a round
added; refs a sent packet withheld under a privacy rule join `ReviewFollowUp.added_refs`, a
withheld captured group's parts with its lead (`withheld_excerpt_content_refs`). Amendment (tb4n5,
ADR-006): `case_excerpt_refs` names only sources a sent packet carried whole, and the in-process
`case_excerpt_parts` (`sent_excerpt_parts`) names each part it carried as a byte interval of its
source (`missing_for_assessment.excerpt_span_key`, from `SemanticCase.excerpt_parts`, local and
never digest material); `ReviewFollowUp.shown_parts` / `added_parts` carry them across rounds, a
round is sent only when `semantic_case.follow_up_new_parts` finds a requested part no sent packet
carried, and a `current_diff_for_path` request naming a captured edit is also answered with the
current `change-section-NNN` section of each path it changed, cut from the frozen check-time change
(`kernel.test_edit_visibility.check_change_sections`). Span keys use the source's own length, and a
head-and-tail clip contributes two intervals. A follow-up case marks the excerpts that supply the
request (`SemanticCase.follow_up_supplied_item_ids`, in its digest); the packet row carries
`follow_up_supplied: true` (governed by `privacy/review-packet-row-2.0.0.schema.json`; absence is compatible) and the provider-bound `missing_inputs` say `supplied` only through such
a row admission kept. The dispatch gate counts only rows the bounded envelope's catalog keeps
(`bounded_catalog_item_ids`). The planner's `section_parts` (`current_section_parts`, carried as the
evaluation's in-process `case_current_section_parts`) asks for a current section only while that
edit's paths have unsent bytes. Served sections join the ADR-031 shown-file record
(`check_time_change_sections_carried`, `check_time_change_shown_record`); a file not shown as one run
from its section's start makes the record incomplete. The evaluator seam takes the
optional keyword `follow_up` (returning `None` when nothing was dispatched); the facade forwards it
only to an evaluator that names it.

`resolution_attempt_required` is the `respond` rejection for an `acknowledged` response to a
`semantic_model_derived` finding whose `evidence_refs` cite no evidence or result recorded after
the finding's own record (not after whichever later in-chain `finding_frontier` the caller named,
#911). It writes nothing; the continuation is `input_correction_new_identity`.
One structural exception applies (issue #906, a process finding): when the finding's kind is the
record-state kind `ledger_stale_or_incomplete`, every `subject_refs` entry is an event recorded as
`check_recorded`, or as `finding_recorded` whose own finding is of that kind and transitively meets
the same rule (never an agent's `response_recorded` answer), and a `check_recorded` event whose
`semantic_status`/`semantic_reason` is `succeeded`/`semantic_completed` follows the finding's source
event, that completed review is the resolution and `acknowledged` is accepted without a new
attempt. Citing a check row is not enough on its own: any other kind, a finding naming any
obligation, claim or other record, or a restatement of a finding about one keeps the rejection.
Acknowledgement still never resolves a finding.

### Observation latency and capacity (#887)

`observation-budget-v3-capacity` uses resource occupancy for admission and effective detail.
`oldest_pending_age_ms` and the historical `max_pending_age_ms` field remain readable diagnostic
values; age alone neither rejects structural input nor disables content. Real count, byte,
session-share, pending-pair and capture limits and recovery dwell remain authoritative. See ADR-029.

### Exact-frontier workflow snapshot reuse (issue #886)

Respond, receipt, check, publish and candidate-finding status use an adapter-owned projection
only when its frontier exactly matches the requested prefix: the live head, or one of at most 16
recent exact frontiers the adapter itself produced by replay or append. A retained frontier is
honoured only while the current chain still holds the identical record objects it was folded
from, so recovery, a rolled-back SQLite sync or any record replacement invalidates it, and a
redaction append drops every retained frontier. Anything else falls back to genesis replay in a
worker thread that stops at the next record when its caller is cancelled. Respond reads a finding
at an older in-chain finding frontier from the current projection when the record at that
sequence carries the requested head digest and the finding's source event is at or before it.

Appends fold only the new records onto the adapter's trusted projection (the whole prefix is
still re-authenticated into a fresh reverse index), so a write no longer re-reduces the ledger
while holding the ledger lock. Receipt-time anchoring of a stale-by-observation frontier accepts
the adapter's own projection by identity instead of replaying on the loop. Folding carries
records unchanged from the already validated prior projection by identity rather than re-encoding
and re-digesting every payload on each step, which had made genesis replay quadratic; new or
replaced records are validated in full. Receipt/candidate/check case assembly still validates
record chains and builds its reverse index, without reducing the already validated prefix again.
There is no process-global task-content cache. Status retains at most eight exact-frontier row
indexes per ledger; append-only extension may reuse pinned pages, while prefix replacement,
truncation or redaction invalidates them. Snapshot reuse never substitutes frontier equality
alone for an adapter's recovery/authentication authority. All host/OS clients share this path.
`tests/integration/application/test_ledger_replay_bench.py` is an opt-in latency benchmark
(`FINISHUP_BENCH_886=1`) at 1,500 and 3,000 observation events.

### Native edit evidence selection

Dedicated visible edit arguments may be retained as `workspace_diff` / changed-file capture content
through the existing observation contract, once per edit from the post-tool event, with
workspace-relative locators and an `applied`/`failed`/`unknown` outcome label. This does not admit
generic command input or ambient repository reads. The shared resolver and the builder rank
claim/assessment-linked evidence first, then captured edits (newest first), then other captures;
a selected capture outside the latest-256 envelope window is read by exact content reference.
Authenticated code uses bounded UTF-8 chunks and preserves `content_unselected` and
`truncated_payload` coverage when caps omit bytes. Successful application and current repository
state remain distinct.
See ADR-006 and the three host integration runbooks for capture and disclosure boundaries.


### Recheck repair evidence (#884 follow-up)

For readable unresolved findings in the frozen case, response `evidence_refs` now establish
excerpt relevance. A directly linked readable result contributes its own evidence refs (one hop,
no recursive traversal). The complete chain must be case-allowed. Capture resolution and packet
selection prioritize this set ahead of other linked evidence, under existing capture, privacy,
count and byte limits. Neither linkage nor acknowledgement changes finding-resolution rules.

### Native capture provenance retention (#883 follow-up)

`SqliteObservationStore` keeps at most 256 observation envelopes per workspace, reserving up to
64 slots for the newest envelopes with content references. Other slots keep the most recent
remaining events. `list_envelopes_for_content_refs` can therefore authenticate retained captures
after routine traffic rolls over the ring, but cannot reconstruct captures evicted from this
bounded reservation. Workspace/session fences and capture/disclosure authorization still apply.
The selection policy is shared by all three hosts and supported OSes; it needs no extra Codex
content profile and does not increase the owner's configured capacity.

The owner-only `service diagnostics` ring also records `semantic_composition/semantic_case_built`
with integer counts: `semantic_capture_parts_resolved`, `semantic_diff_parts_resolved`,
`semantic_excerpts_selected`, `semantic_diff_excerpts_selected`,
`semantic_excerpt_bytes_selected`, `semantic_check_change_parts_selected` (ADR-031 parts in the
packet), and `semantic_edit_evidence_in_case` (materialized native edit captures in the frozen
case, before any resolver fence; zero beside known native edits means their captures never reached
the ledger). Resolved parts have passed capture authentication; selected excerpts are in the built
packet. These counts precede privacy minimization and do not prove provider delivery or code
correctness. The record contains no content, paths, or content hashes.

### Review dialogue record (issue #905)

`finding_recorded` `1.3.0` (unreleased on the 0.3 line, extended in place) admits two optional
review-dialogue fields on an AI-powered finding only: `challenge` (the reviewer's `discrepancy`,
`alternative_interpretation`, `requested_next_step` and `uncertainty`, each bounded like the
provider challenge) and `relates_to` (1–16 earlier recorded finding ids the challenge cited; never
the finding's own id). Released versions never carry them. Local findings, and AI-powered findings
without these fields, keep the bytes earlier 0.3 builds wrote, and those rows still validate, so
old ledgers replay unchanged. The public `finding` object (check result, status, receipt) stays
closed at 1.3.0 and carries the challenge only as `summary` and `detail`.
`fixtures/canonical/review-dialogue-1.3.0.case.json` locks the rows with and without the fields.

A cited `fnd_` in a challenge resolves to that finding's subjects when it is a local finding of
the same check or a readable recorded finding inside the frozen fence; only already-recorded
findings are kept as `relates_to`, so a link never names a finding that was ranked away.

A provider challenge may name the finding it restates (`restates`, provider-judgment `1.2.0`,
optional; issue #980). It folds only when the challenge's `finding_kind` equals the named
finding's kind. A carried readable open AI-powered finding (one of `prior_finding_refs`): the
challenge mints nothing; the check records `answered_not_fixed` (the agent had answered) or
`still_present` on that finding, citing the challenge's refs, and appends the challenge's summary
and message to `review_summary` under a fixed header naming the id. A carried settled finding (a
`yoetz.settled-finding/1` row; `SemanticPacketView.settled_finding_refs`, passed to
`validate_semantic_judgment(settled_finding_refs=)`): the challenge mints nothing and a
`still_present` ruling is recorded on the final item, which the reducer counts in
`settled_reraise_count` (no round, never reopened). Any other target (another kind, a resolved or
final item, an uncarried finding) yields a new finding whose `relates_to` names it and records no
ruling on it. A `restates` is never
counted in `semantic_review_refs_reduced`; an id outside the fence is ignored.

Dialogue projection facts (TB4 tb4n1 D7): a finding row counts the agent's `rejected` and
`self_verified` responses (`rebuttal_count`), keeps the newest admitted ruling
(`last_reviewer_verdict`), and counts re-raises recorded after the agent settled it
(`settled_reraise_count`, rulings `still_present`/`answered_not_fixed` on an item whose latest
response is `acknowledged_not_done` or `self_verified`); all are replay-derived, emitted in
projection snapshots only when set, and carried on the `yoetz.prior-finding/1` /
`yoetz.settled-finding/1` rows when set. `kernel.finding_todo.premise_dispute_basis(state,
finding_id) -> "blocker_cited" | "give_up_reraised" | None` and
`standing_premise_disputes(state, finding_ids=None)` (`FindingTodo.premise_disputed`) flag an
`acknowledged_not_done` AI-powered `task_requirement_unmet`/`requested_item_never_attempted`
finding that asked the agent to `act` only with a recorded anchor: its subject refs cite a
readable, unsuperseded `finishup-blocker` decision or an obligation it blocks, or
`settled_reraise_count > 0`. The acknowledgement stays final; the dispute is for readiness or
Stop surfaces.

The prior-findings section also carries, after the open findings and inside the same bounds,
non-rulable `yoetz.settled-finding/1` rows (item ids `settled-finding-<ref>`, prose
`settled-finding-summary-<ref>` and `settled-finding-response-<ref>`) for readable, unresolved
AI-powered findings the agent settled; they never enter `prior_finding_refs`, a ruling on one is
set aside, and one that does not fit adds no `semantic_prior_findings_over_limit`.

The review packet (`outbound-case` `1.2.0`) adds the `prior_finding` section,
`review_packet.prior_finding_item_ids` (every row of the section, at most 112) and
`review_packet.prior_finding_refs` (the ruling unit: each carried finding's `finding_ref` exactly
once, newest first, at most 16, listed only while its structural row is carried). It carries the newest readable, unresolved AI-powered
findings (at most 16, 96 KiB of item content (issue #976; 8 and 48 KiB before), and only case capacity the other sections leave;
outside the timeline's 64 rows, so hook rows never crowd it out). Under egress-envelope pressure its
rows are removed first, oldest finding first, before any other bounding step, so the section never
displaces work content; removed rows count in `catalog_dropped_count` and add
`semantic_prior_findings_over_limit`. Each carried finding has one
`yoetz.prior-finding/1` structural row per finding (kind, ids, recorded sequence, requested next
step, `relates_to`, the latest response disposition, cited refs and recorded sequence, and the
readable evidence/results recorded after the finding) plus, where the profile already sends
finding prose, the summary, message, challenge fields and response reason as
`finding_summary` rows. No new data category crosses egress. A finding recorded without
challenge fields (by an earlier build) degrades to summary and message with a `not_recorded` omission. Findings the section cannot carry
are `not_selected` omissions and add `semantic_prior_findings_over_limit` to coverage. That code
is a selection gap, but of the dialogue view, not of the work under review: it stays on the receipt
and is deliberately tolerated by both finding-resolution proof classes (unlike the selection gaps
issue #904 classifies), because a partial dialogue view is no weaker than the review before the
section existed. A finding recorded without challenge fields is disclosed through its structural row
(`challenge_fields: not_recorded`) and a `not_recorded` omission rather than a coverage gap: its
record is complete for its version, and nothing it lacks was lost.

The provider judgment is `provider-judgment` `1.1.0`: every conclusion branch requires
`prior_finding_verdicts` (0–8 of `{finding_id, verdict, cited_refs, note}`, 0–16 in the unreleased
`1.2.0` extended in place for issue #976; `verdict` ∈
`fixed|still_present|answered_not_fixed|unassessable|withdrawn`), for the Codex app-server,
Responses and Chat Completions cells alike (the prompt-only Chat Completions shape names it too).
The reviewer returns exactly one ruling per `finding_ref` in `review_packet.prior_finding_refs`,
never one per prior-finding row; the shared instruction says so for every provider cell. The
shared normalizer folds rulings by `finding_id` before applying the cap: the first ruling on a
finding stands, each repeat counts as dropped, and a repeat with a different verdict makes that
finding's ruling `unassessable` with no cited refs.
A reply that omits the array (the 1.0.0 shape a local model or prompt-only host may still return)
is read as carrying no rulings; a malformed or surplus ruling is dropped and counted instead of
failing the judgment. Post-validation admits and bounds each ruling as ADR-006 describes, fenced to
the prior-findings rows and `citable_refs` of the packet the reviewer was actually shown (a ruling
on a readable open finding the packet did not carry is recorded as `unassessable`); admitted
rulings are recorded as
the optional `check_recorded` `1.3.0` field `prior_finding_verdicts` (`{finding_id, verdict,
cited_refs}`, 1–16 (issue #976), ASCII-sorted by finding id, never the note; unreleased 1.3.0 extended in place),
present only when at least one ruling was admitted, so a check without rulings keeps its bytes
(issue #907's optional `missing_for_assessment` shares the version the same way).
`semantic_prior_verdicts_unsupported` discloses dropped or reduced rulings and, like
`semantic_prior_findings_over_limit`, is tolerated by both proof classes. A ruling on an item that
is already final (`verified_resolved`, `acknowledged_not_done`, `rejection_accepted`), or one the
same review's restatement contradicts, is set aside instead: it adds no gap and is counted only as
the `semantic_prior_rulings_set_aside` diagnostic. Tolerated means they never veto
a ruled row: on a check carrying either code, a `semantic_model_derived` row the check recorded no
ruling for gets the blocker `reviewer_assessment_incomplete`, because the review may not have
seen it (section limit, envelope trimming, or a selection without the assessments section, which
also adds `semantic_prior_findings_over_limit`) or its ruling may have been dropped. Such a row
never resolves by silence on that check. For a
`semantic_model_derived` row, a recorded `fixed` ruling on that row lifts the
`insufficient_packet` veto and tolerates `semantic_packet_insufficient`, the named-missing-item
codes and `content_unselected` (excerpts the packet's count or byte budget cut, ledger or captured;
issue #907) for that row only: the reviewer affirmatively ruled the finding fixed, citing refs that
are fenced to the packet's `citable_refs`, so it assessed the finding on material it was shown.
Silence gets no such tolerance, so a selection gap still blocks closing a row by not returning it;
`withdrawn` keeps the ordinary rules (an assessable review that does not re-raise a finding over
changed state proves it absent) and never lifts the veto, but on a finding whose latest readable
response is `rejected` that check records `rejection_accepted`, not resolution (below);
`still_present`, `answered_not_fixed` and
`unassessable` add the blocker `reviewer_verdict_<verdict>`. The resolution explanation names a
resolution that came from a `fixed` ruling.

#### Finding to-do states and `acknowledged_not_done` (issue #905)

`acknowledged_not_done` is a `respond` disposition: the agent states, with a required non-empty
`reason` (at most 4096 bytes), that it will not do what the finding asks. It accepts no waiver
fields. A missing `reason` fails the request schema; a whitespace-only one is refused with
`INVALID_REQUEST`, reason code `response_fields_invalid`, field `/reason`. It is carried only by
`respond-request` `1.1.0`, `respond-result` `1.1.0` and the `response_recorded` `1.1.0` event, all
new because their 1.0.0 predecessors are released; every other disposition is still recorded as
`response_recorded` `1.0.0`, so the event version is a pure function of the payload. Control
`2.9.0` (unreleased, changed in place) references the respond 1.1.0 pair. Every earlier control
version keeps the 1.0.0 pair: the released ones (v0.2.5 ships control up to `2.6.1`) and the
unreleased `2.7.0` and `2.8.0` of earlier 0.3 builds, so an older service refuses the disposition
at its schema boundary. `status-request`
`1.2.0`, `status-result` `1.4.0` and `receipt-document` `1.3.0` admit the value in place.

Every recorded finding has one to-do state (`kernel/finding_todo.py`): `open`,
`verified_resolved` (the shared `finding_is_resolved` rule), `acknowledged_not_done` (latest
readable response has that disposition; reads as resolved only through a later absence proof, below), or `rejection_accepted` (a later
check recorded a `withdrawn` ruling on an AI-powered finding whose latest readable response was
`rejected`; the projection records the check as `rejection_accepted_by_check_event_id`). When the
same check also satisfies the absence proof for that row, the explicit ruling wins:
`apply_check_rulings` clears that check's `resolved_by_check_event_id` and latches
`rejection_accepted`, so the row has one final state. A row an earlier check resolved stays
`verified_resolved`. The last
three are terminal: `respond` on a terminal finding appends nothing and fails with
`INVALID_REQUEST`, reason code `finding_terminal`, field `/finding_id` (no continuation: there is
nothing to do); a latched row is never resolved later; redacting the latching check clears the
latch. Terminal items are left out of the prior-findings section and rulings on them are not
admitted. `receipt_blocking_finding_count` counts `acknowledged_not_done` rows of a requirement kind that demand work (an
acknowledged `action_without_result` bookkeeping finding is disclosed instead, ADR-046; a reviewer's limitation
request is never counted) and no longer counts `rejection_accepted` rows.

#### `self_verified`: proof-limited findings (issue #984, ADR-034)

`self_verified` is a terminal `respond` disposition for a finding the agent repaired that FinishUP
cannot prove repaired because of its own limits (a *FinishUP limit*: capture, redaction or observation
loss, review-packet limits). It requires `reason` (non-blank, at most 4096 bytes: how the agent
verified the repair) and 1–64 `evidence_refs` naming recorded `evd_`/`res_` ids of this task (any
evidence version, strength or content availability); it accepts no waiver fields. It rides the same
`respond-request`/`respond-result` `1.1.0` and `response_recorded` `1.1.0` versions as
`acknowledged_not_done`. Typed `INVALID_REQUEST` refusals: `response_fields_invalid` (`/reason`
blank, `/evidence_refs` empty), `finding_terminal`, `finding_not_rechecked` (no later check tested
the finding: repair, then `check`), `finding_not_proof_limited` (the newest check that could resolve
it still sees it or names agent work); the last two continue as `input_correction_new_identity`.
`finding_not_proof_limited` carries `safe_details.blocking_reasons`: the 1-32 recorded
resolution-reason tokens that disqualified it (`self_verification_blocking_reasons`, matching
`^(coverage:)?[a-z][a-z0-9_]{0,95}$`, `no_recorded_limit` when the check recorded none), and its
message names them with a next step and the `finishup-verification-limit:<obligation id>` exit
(ADR-041).
Eligibility is `kernel/self_verification.self_verification_refusal(state, finding_id, records)`
over the resolution reasons of that check (ADR-034): any `coverage:<code>` classified standing in
`GAP_CLASSIFICATION` is a FinishUP limit. The to-do state `self_verified` is not resolved by its own
answer (`finding_is_resolved` is false for it unless a qualifying check tested the work after the
answer; see "Reverse edges" below), is not counted by
`receipt_blocking_finding_count`, is left out of the next review, and is disclosed: closure
readiness lists the standing code `finding_self_verified`; `receipt-document` `1.3.0` carries
`self_verified_finding_ids` (1–100, a `no_unresolved_deterministic_findings` conclusion beside it is
invalid) and markdown/text render a "Self-verified by the agent; FinishUP could not prove the repair"
section; the conclusion is at best `insufficient_coverage`. `check-result` `finding_checklist.counts`
and the status findings view carry `self_verified` as a count and a `todo_state`.

#### `disputed_after_rebuttal`: a standing reviewer disagreement (issue #1020, ADR-040)

`disputed_after_rebuttal` is a recorded reviewer ruling and a final to-do state that FinishUP, not the
reviewer or the agent, assigns. `_admit_prior_verdicts` records it in place of a `still_present` or
`answered_not_fixed` ruling on a shown AI-powered finding whose latest readable
response is `rejected` with a non-blank reason, when the ruling cites no `evd_`/`res_`/`act_`/`evt_`
material recorded after that response (findings, claims and obligations are not material). Since the
tb4n5 amendment (ADR-040, 2026-10-13) an `unassessable` ruling, and an unsupported `fixed` or
`withdrawn` demoted to it, stay `unassessable` (an open round), and a `fixed` ruling's `evt_`
citation resolves to the evidence or result that event recorded before the after-the-finding test
(`_ruling_material`); an acknowledgement with a reason still counts as the standing position (#1030).
The open `unassessable` round is bounded: `review_round.unassessable_review_exhausted` stops the
review round (`semantic_review_skipped_insufficient_packet`) after two completed reviews in a row
ruled one finding `unassessable` with no edit since, or four in a row; the finding stays open and
unresolved; a `semantic_required` check still runs its review.
The resolution explanation of a latched row names it whatever the latest disposition, with no repair
instruction; `respond` on it, or on a `verified_resolved` row, returns `finding_terminal` with a
message that says nothing is owed. A
challenge restating such a finding (by `restates`, the restatement key, or a reply naming it)
records the same ruling. `apply_check_rulings` latches `disputed_after_rebuttal_by_check_event_id`
on a readable rejection, counts no review round, and never lets a later check upgrade the row to
`verified_resolved`; redacting the latching check clears the latch. The state is terminal
(`respond` answers `finding_terminal`), not counted by `receipt_blocking_finding_count` or the
Stop gate, carried to later packets as a non-rulable `yoetz.settled-finding/1` row, and never clean:
closure readiness lists the standing code `finding_disputed_after_rebuttal`; `receipt-document`
`1.3.0` carries `disputed_after_rebuttal_finding_ids` (1–100, a clean conclusion beside it is
invalid) and markdown/text render a "Disputed after rebuttal" section; the conclusion is at best
`insufficient_coverage`. `check-result` `finding_checklist.counts.disputed_after_rebuttal` is
present only when non-zero; the status findings view carries the `todo_state`. `check-recorded`
`1.3.0`/`1.4.0` `prior_finding_verdict.verdict` admits the value; the provider judgment schema does
not.

Restatement matching (`_restated_finding`) tries the exact subject set first, then the same kind
over `_concern_key`: claims mapped to their current superseding claim, and only the obligation set
when both sides name obligations; every ref but a claim must still be no newer than the earlier
finding, or than the agent's reasoned rejection when nothing after that rejection is cited. During a
routine review (the phase the packet named; with no phase passed, before any effective completion
claim) an AI-powered `requested_item_never_attempted` challenge is dropped and counted under the
rejection reason `routine_completeness`; the closing review keeps it even without a completion claim
(issue #1042). In every phase a challenge whose every subject is FinishUP's own capture or process record
(`kernel.review_frame.finishup_process_state_only`: the hook observation of a call to one of FinishUP's own
tools or its result, or, for `action_without_result`, any hook-observed action) is dropped and
counted under `yoetz_process_state`. An `action_without_result` or `result_without_action`
challenge whose cited records show only the pairing gap the local rule decides over the whole
ledger (`kernel.review_frame.local_rule_owned`, tb4n5 follow-up of #1042: every cited event is an
unpaired readable action, or a successful orphan result, at least one, plus at most evidence no
claim and no unsuccessful result cites) is dropped and counted under `local_rule_owned`; one citing
a paired action, a claim, an obligation, a failed run or anything unreadable is kept. Those three
reasons add the
standing disclosure
`semantic_process_state_filtered` (gap table rule G5d: disclosed on both routes, tolerated by both
absence proofs) instead of `semantic_challenges_rejected`, which keeps bounding for every other
dropped challenge. The bounded accounting record names each reason
(`semantic_rejected_<reason>`) and the advisory and agent-criterion counts below.

A receipt whose applicable check is followed only by responses to that check's own findings
(`CheckSuffixClass.RESPONSES_ONLY`) treats `check_current_as_of_earlier_frontier` as a disclosure
(issue #1021); any other counted later material keeps it bounding the conclusion. "Counted" excludes
what `later_material_class` proves harmless (FinishUP's own calls, read-only reads, host bookkeeping,
scratch or FinishUP-owned writes; ADR-040 section 7, tb4n3 RC-6). While the counted suffix bounds,
`check_current_as_of_earlier_frontier` stays a standing limitation in `closure_readiness` (not
agent work: a recheck-instruction can regenerate, ADR-040 section 7); `closure_readiness.check_cause`
(optional) names the first record that superseded the check (beside `check_not_applicable`) or that
the bounding suffix rests on (beside the standing code): `effect`, `event_id`,
`ledger_sequence`, `family`, `material_class`, `rule`, optional `tool`, `check_event_id`,
`check_subject_frontier`.

#### Reverse edges, limitation requests and concern identity (issues #1024 and #1030, ADR-034 and ADR-040 amendments)

Names shared by the kernel, `respond`, `check`, status and the receipt:

- `respond` disposition `reopened` (with `acknowledged_not_done` it rides `respond-request` and
  `respond-result` `1.1.0` and the `response_recorded` `1.1.0` event; `reason` is required): takes an
  `acknowledged_not_done` answer back, the finding is `open` and its standing position is retracted.
  Refused with `response_fields_invalid` on `/disposition` on any other state. `verified_resolved`,
  `rejection_accepted` and `disputed_after_rebuttal` stay absolutely final (`finding_terminal`);
  `acknowledged_not_done` answers `finding_terminal` to every disposition but `reopened`; the message
  names the state and the way out.
- `respond-result` `1.1.0` optional `closure_after {todo_state, limitation?}`: the state the answer
  produced, simulated at its own frontier (`limitation` is `limitation_requested`,
  `limitation_disclosed` or `limitation_acknowledged_not_done` for a reviewer's limitation request;
  absent otherwise).
- Absence proof after the answer: `FindingProjectionRecord.resolution_frontier` (the tested frontier
  of the check named by `resolved_by_check_event_id`) lets `finding_is_resolved` resolve an
  `acknowledged_not_done` or `self_verified` answer when the proof tested the work after the answer.
  The status finding items allow `resolved: true` on those two states.
- Limitation requests: `domain.findings.is_limitation_request(finding)` and
  `finding_demands_work(finding)`; `kernel.limitation.limitation_standing(state, finding_id) ->
  LimitationStanding | None` with states `limitation_requested` (to disclose),
  `limitation_disclosed` (the requirement may be met but cannot be verified here; basis
  `respond_acknowledgement` or `verification_limit_decision`) and
  `limitation_acknowledged_not_done` (the requirement is NOT met; basis
  `respond_acknowledged_not_done`; `LimitationStanding.unmet`), `limitation_requested_ids` and
  `limitation_disclosed_ids`. The agent's answer decides which (owner decision 2026-10-12; the
  answer is read before a decision line, so a decision never turns `acknowledged_not_done` into a
  disclosure). Until answered a limitation request never demands work, is never receipt-blocking and
  is never clean; answered `acknowledged_not_done` it is `settled_unmet` and holds the receipt at
  `unresolved_findings_remain`. Acknowledging it needs no recorded resolution attempt.
- Reducer facts (replay-derived, snapshot-emitted only when set): `standing_position`
  (`StandingPosition(kind, frontier)`; the earliest unretracted reasoned answer), `last_ruling_frontier`,
  `resolution_frontier`, `absorbed_refs` (bounded refs a settled item's re-raises cited) on a finding
  row; `introduced_frontier` on an obligation row (its first publication; republication only changes
  status). Accessors: `kernel.finding_todo.finding_standing(state, id) -> (kind, frontier) | None`,
  `ruling_since(state, id) -> int | None`, `standing_answer_frontier(state, id) -> int | None`.
- Concern identity: `kernel.concern.concern_key(projection, refs) -> ConcernKey`, `same_concern`,
  `equal_concern`, `kinds_comparable`; new material: `application.review_concern.concern_material_after`
  and `answer_bound`. Packet: `yoetz_already_disclosed` beside an obligation the agent disclosed and
  `limitation_already_disclosed` / `limitation_disclosed_by` on a settled-finding row.

#### `duplicate_of`: a re-raised finding linked to an earlier one (issue #996, ADR-034 amendment)

`duplicate_of` is a non-terminal `respond` disposition for a genuine restatement: a finding that
names the same issue as an earlier finding the agent already answered or is answering (a re-raise
minted as a new finding that automatic `restates` linking missed). It requires
`duplicate_of_finding_id` (a `fnd_` id, admitted only with this disposition); `reason` and
`evidence_refs` are optional; waiver fields are refused. It rides `respond-request`/`respond-result`
`1.1.0` and `response_recorded` `1.1.0` (the result and event echo `duplicate_of_finding_id`).
Typed `INVALID_REQUEST` refusals, each continuing as `input_correction_new_identity`:
`duplicate_target_same_finding`, `duplicate_target_unknown` (not a readable finding of this task),
`duplicate_target_not_earlier`, `duplicate_target_different_issue` (a different origin or kind),
`duplicate_target_is_duplicate` (the target is itself linked; the message names the finding to link
to), `duplicate_has_duplicates` (other findings link to this one) and `duplicate_link_broken`. A
link holds (`kernel/projections.duplicate_link_holds`) while both findings are readable, the target
is earlier with the same origin and kind, and no remaining readable check broke it. While it holds
the duplicate inherits only `self_verified` and `acknowledged_not_done`; it never inherits
`verified_resolved` or `rejection_accepted` and otherwise stays `open` but answered: linking never
resolves a finding, only its own qualifying check does. Readiness names an open or inherited pair
once by the earlier finding (`finding_todo.duplicate_counting_id`); an open duplicate of a settled
or non-actionable earlier finding counts on its own. The link breaks while any later readable check
returned the duplicate again, returned a local finding with its issue key, or ruled it
`still_present` or `answered_not_fixed`: the projection records
`duplicate_link_broken_by_check_event_ids` (emitted in snapshots only when non-empty; redacting a
check removes only its id). A broken link or an unreadable earlier finding leaves the duplicate
unanswered. A linked duplicate stays in the next review's prior findings (with `duplicate_of_ref`)
and rulings on it are admitted. The status findings row carries `duplicate_of_finding_id` exactly
while the link holds; `receipt-document` `1.3.0` carries `duplicate_finding_links` (1–100
`{finding_id, duplicate_of_finding_id}`, ids only, each `finding_id` a carried finding) and
markdown/text render a "Linked duplicates" section. A child's frozen finding rows read `resolved`
from the child receipt's to-do predicate and roll a counted-once pair up as one row. Status
`view=lineage` children carry `self_verified_finding_count` (present only when positive), and
status readiness lists the standing code `finding_self_verified` when an accepted child has one.

`review_rounds` counts later recorded checks that assessed a finding and left it open: a check that
returned a local finding again over a later subject, or a recorded `still_present`,
`answered_not_fixed` or `unassessable` ruling. Projection snapshots emit `review_rounds` and
`rejection_accepted_by_check_event_id` only when set. A snapshot rebuilt from an old ledger keeps
its bytes unless that ledger has a local finding a later check returned again over a later
subject: replay now derives `review_rounds` for it. Resolution and receipt outcomes are unchanged,
and the snapshot projection version is not bumped because the field is additive. The
owner's `verification.finding_attempt_budget` (`yoetz-config` `1.3.0`, integer 1–50, default 5;
`FINISHUP_VERIFICATION_FINDING_ATTEMPT_BUDGET`; written to the file only when not the default) is the
round count at which an open item asks for a decision. It never throttles `check` and never
changes state.

Check `1.4.0` preserves the earlier checklist and adds frozen-work `totals` to every newly
completed check, including insufficient-coverage and failed required-review results. Legacy
events without totals remain readable; an awaiting-input or awaiting-human continuation is not
a completed check and has no claimed accounting result. Counters are canonical unsigned strings
under closed keys for effective-plan obligations, obligation-scoped requested-item attempts,
service-observed commands, evidence strength, and returned/suppressed findings. The current
finding-disposition counts remain in `finding_checklist`, distinguished from frozen-work totals.
Failed exploration stays in historical command counts. A later qualifying run of the same keyed
command identity can retire a failure; unrelated edits and unknown reruns cannot. A disclosed test
failure remains live until rerun green. An attempted item or linked evidence record is an assertion
or link, not a claim that the requirement was verified. Totals survive event replay and operation
recovery without recounting newer work, and carry no command text, paths, or caller-defined keys.

The totals field `obligations.scope_known` is a canonical `"0"`/`"1"` availability flag. It is
`"1"` when the current plan declaration is readable (including a readable empty or absent plan)
and `"0"` when that scope is redacted, malformed, or otherwise unavailable. When it is `"0"`,
the obligation and obligation-scoped requested-item counters are unavailable rather than observed
zeroes, the receipt says so, and the scoped deterministic verdict is ineligible. The
`test_edits.examined` and
`test_edits.baseline_known` totals are the same binary availability shape; all other totals remain
canonical unsigned counters.

**Optional pre-check observation wait (#1012).** `check-request` 1.1.0 accepts the optional boolean
`await_observations` (MCP `check`, `finishup check --await-observations`). When `true`, the daemon,
before either dispatch gate, reads the pending local hook outbox rows of every host session whose
lifecycle mapping names the request's FinishUP session
(`adapters/integrations/observation_task_pending.session_pending_row_identities`, the same task
rule as the Stop gate's `observe_hooks._task_pending_outbox_count`), wakes the observation sweeper
and polls real local state (`application/observation_await.await_task_observations`) until none of
those snapshot rows is pending or `min(3 s, deadline / 10)` passes. The result then carries the
closed `observations_awaited` member of `check-result` 1.4.0 — `state` `complete`,
`bounded_timeout` or `unavailable`, and `pending_count` (canonical unsigned string, `"0"` unless
`bounded_timeout`) — and only when the request set the flag. The flag is excluded from the check
request digest and the detached-check identity; the member is never recorded in the ledger or
`check_recorded`. The wait never fails a check. Golden vectors: CAN-016
(`fixtures/canonical/check-observations-awaited-1.4.0.case.json`). ADR-029 amendment of
2026-10-07 owns the decision. Since the tb4n5 amendment (2026-10-13) the snapshot also covers the
task's Codex rollout rows held for their hook post: `release_held_rollout_items_for_check`
(`adapters/integrations/codex_session_stream`) delivers each one read at least
`HELD_ROLLOUT_CHECK_RELEASE_SECONDS` (10 s) earlier with `unpaired_event`, and a younger one counts
as pending under the stable identity `stream-input:<source identity>` (the same identity a rollout
row keeps in the outbox), so `pending_count` includes held rows still undelivered. The member's
shape is unchanged.

**Inspection check (`mode: inspect`, #1048).** `check-request` 1.1.0's `mode` admits `inspect`
(unreleased, in place). It is a read routed like `status` (payload read, no write capability): it
freezes no case, appends no event, writes no operation record, mints no finding, dispatches no
reviewer and egresses nothing, so the daemon, the MCP bridge and the CLI classify it as read-only
by one set of modes (`protocol/recovery.READ_ONLY_CHECK_MODES`): a failure, a timeout included, is
a retryable read failure answered by a fresh request (`read_timeout_new_identity`, no
`replay_request_id`), never a same-`request_id` replay, and the daemon never runs it detached. The
bridge gives it the `status` call deadline. The MCP `check` descriptor and its annotations are the
same for every mode, so a host approves, holds or admits an inspection exactly as any `check`
(ADR-047 host decisions; the host runbooks record each host). The request model refuses
`final_review`, `max_findings`, `policy_packs` and `scope` beside it, each at its own field with
reason `extra_forbidden` (kept out of the JSON Schema: a root conditional lowers the advertised
check input to `unknown` on observed hosts);
`await_observations` is accepted and reported as on any check. `expected_frontier` is not
compared. The answer is the `inspection` branch of `check-result` 1.4.0 (`state: inspected`,
discriminated beside `complete` and `awaiting_human`/`awaiting_input`; no verdict, findings,
coverage, versions or `result_frontier`), every leaf structural:

- `subject_frontier` — the frontier read.
- `remaining` — `readiness`, `predicted_conclusion` (optional), `agent_actionable` and
  `standing_limitations` exactly as `status` `closure_readiness` prints them at that frontier
  (`application/status.current_closure_readiness`, ADR-046); `obligations` (at most 64; count in
  `obligation_count`) — every effective obligation whose class is not `resolved`, as
  `{obligation_id, closure_class, closure_basis, missing}`, agent work first; `missing` (at most 8)
  names `{kind, owner, item_indexes?}` with `kind` `requested_item_not_attempted`,
  `resolution_evidence_not_cited`, `command_attempt_mismatch`, `blocker_unconfirmed` (owner
  `agent`) or `command_run_not_observed` (owner `finishup`: an asserted command attempt with no
  linked hook observation); `findings` (at most 64; `finding_count`) — every finding whose class is
  not `resolved`, as `{finding_id, closure_class, closure_basis}`.
- `observed_since_check` — `last_check_frontier` (absent before any check), `action_count`, and
  the newest 64 hook-observed `action_recorded` rows after that frontier whose `later_material`
  class is `edit_or_write`, `exploration`, `non_counting_write` or `other` (FinishUP's own calls and
  host bookkeeping are not listed): `{event_id, ledger_sequence, action_kind, material_class,
  tool_name?, write_scope?, outcome?, exit_status?, command_commitment?}`. Observed edits record a
  write class, never a path.
- `evidence_alignment` — `basis: recorded_links`, `obligation_count` and `off_declared_count`
  (every row and every `evidence_off_declared_items` row, counted before the bound) and, for each
  effective obligation citing `resolution_evidence_refs` (at most 64, flagged rows first, then by
  id), its declared items (requested `command` items and `file`/`directory` items whose role is
  not `input`, by index and kind), and per cited ref the `origin` (`observed`, `asserted` or
  `unattributed`) of the action behind it (a result's action; for evidence, the actions of results
  that cite it and an action named in its `causal_parents`), that action's keyed
  `command_commitment`, the result `outcome`, and `named_item_indexes` — the declared items its
  `attempted_items` name (ADR-045 path matching) or, for a requested command, that its observed
  keyed run matches (the shared planned-command matcher; an asserted command matches only byte for
  byte). `alignment` is `no_declared_items`, `evidence_names_declared_item`,
  `evidence_off_declared_items` (some cited evidence traces to an action and none names a declared
  item) or `evidence_unattributed`. FinishUP records no command text, working directory, environment
  or service configuration; this compares only those recorded links.

CLI and MCP print the same lines (`protocol/inspection_text`). Golden vectors: CAN-017
(`fixtures/canonical/check-inspection-1.4.0.case.json`). ADR-047 owns the decision.

A check whose effective mode is deterministic-only can say **no issue detected within
deterministic coverage** when its complete candidate set, active obligations, requested items and
relevant observed failures permit it. An omitted mode resolves through the configured verification
policy; a disabled semantic policy therefore uses this same deterministic-only route, while an
optional or required semantic route does not. The absence of AI-powered review remains in coverage
and the receipt; no open/unreadable obligation, unattempted item, unknown command outcome, relevant
live failure, actionable finding (even suppressed), or material coverage gap can earn this scoped
verdict.
[ADR-032](adr/ADR-032-closure-readiness-checklist-and-material-dependency-coverage.md) owns the
closed standing-limit allowlist and the unchanged receipt honesty boundary.

Wire (the earlier checklist fields remain available in their original versions):

- `check-result` `1.3.0` success: optional `finding_checklist` `{attempt_budget, counts, items[],
  next}`. `attempt_budget` is a canonical string `1`–`50`; each item is `{finding_id, todo_state,
  review_rounds}` (at most 100: the current actionable items, newest row per issue, open items
  first and otherwise in rank order, final rows included; coverage limitations are not to-dos);
  `next` is `decide_at_budget` (an open item reached the budget: repair with new evidence or
  respond `acknowledged_not_done`), `work_open_findings`, `disclose_limitations` (the only agent
  work left is a reviewer's limitation request nobody answered; `check-result` 1.4.0, owner
  decision 2026-10-12; an open `agent_criterion_unmet` is work, `work_open_findings`), or
  `request_receipt`. It is current
  projection context attached after the commit, like advisory notes, and is omitted when that read
  is unavailable; it is never part of the check event.
- `status-result` `1.4.0` findings view: each row carries `todo_state` and `review_rounds`
  (canonical uint string); the page carries `attempt_budget`.
- `receipt-document` `1.3.0` (issues #995, #997, #984 D7a): optional `disclosed_assumptions`
  rows `{obligation_id, kind: assumption|verification_limit, decision_event_id}` (conclusion
  unchanged), `acknowledged_not_done_obligation_ids` (conclusion never
  `no_unresolved_deterministic_findings`) and `premise_disputed_finding_ids` (a subset of
  `acknowledged_not_done_finding_ids`), each present only when non-empty, ids and closed tokens
  only, each with its own markdown/text section.
- `receipt-document` `1.3.0` (issue #1017, ADR-032 amendment of 2026-10-08): a `gaps` row may
  carry `status: "historical"` with `cleared_at_frontier` (a frontier object); both appear
  together and only on a historical row, and an absent status reads as `live`, so earlier receipts
  decode unchanged. Domain: `ReceiptGap.status` (`ReceiptGapStatus.LIVE` | `HISTORICAL`) and
  `ReceiptGap.cleared_at_frontier`. A row is historical when its code reached the receipt only
  through a retained finding's coverage (`retained_finding_coverage:<code>`), an earlier
  `check_recorded` through the latest tested check carried it, and that latest check does not;
  `cleared_at_frontier` is the subject frontier of the first check after the last one that carried
  it (`application/receipt._historical_gaps`, replay-only). A code is never both live and
  historical on one receipt, and only the 1.3.0 artifact writes the field. The document's
  `coverage.known_gaps` keeps the full union (retained findings still carry the code); the receipt
  conclusion (`kernel/receipt_builder._conclusion`), the limitations section and the compact
  sentence consider live gaps only, and the receipt *result*'s top-level `coverage.known_gaps`
  names live gaps only (`domain/receipts.live_receipt_gap_codes`), so the CLI "Limitations" line,
  the MCP receipt summary count and the terminal interface never count a historical gap. Markdown
  and text add a "Cleared earlier (historical)" section (`historical_gap_line`: code, clearing
  frontier, and the code's fixed sentence); the CLI JSON rendering and the MCP summary name them
  apart (`historical_gaps_from_wire`).
- `receipt-document` `1.3.0`: optional `acknowledged_not_done_finding_ids` and
  `rejection_accepted_finding_ids` (sorted, 1–100, each a carried finding; absent when empty). The
  markdown and text renderings add "Acknowledged, not done" and "Rejection accepted" sections that
  name finding ids only. The redacted-share profile drops `acknowledged_not_done` responses like
  other reasoned dispositions and counts the redaction. Only an artifact that carries these
  sections lets a `rejection_accepted` row stop blocking its conclusion; on an earlier artifact the
  row still counts as unresolved and is listed as such. A child's terminal rows stay actionable
  and unresolved in a parent's lineage rollup (the frozen child snapshot has only `actionable` and
  `resolved`); the child's own receipt discloses them.
- `check-result` `finding_checklist` also carries `counts` (`open`, `open_at_budget`,
  `verified_resolved`, `acknowledged_not_done`, `rejection_accepted`) over every current actionable
  item, and is read from the adapter-owned projection at the result frontier, never from a status
  page or a replay; any failure reading it omits the list and records a
  `finding_checklist_read` diagnostic instead of failing the committed check.
- `missing_for_assessment` is the authoritative input continuation when it contains an
  `agent_suppliable` item: supply or repair the named target before requesting an ordinary receipt.
  The additive `overall_next` projection carries the task-level `status`, `action`, and bounded
  `target_refs`; its `action` is `supply_missing_input` for those targets (the refs may be empty
  when the reviewer named a global input), `work_open_findings` for open findings,
  `disclose_limitations` when the only open findings are reviewer limitation requests nobody
  answered (`check-result` 1.4.0; the targets are those requests; the agent's own open
  `agent_criterion_unmet` is `work_open_findings`),
  `review_recorded_work` for open obligations, undisclosed live failures or a delivered file that
  loads an undeclared file (`deliverable_references_undeclared_file`, #1044; the target is the
  referencing obligation, which stays `resolved`), or `request_receipt`
  when no agent action remains. The finding checklist's `next` remains finding-only and is labeled
  that way beside this continuation. When only standing or structurally unavailable limits remain,
  `overall_next.status` is
  `ready_with_limitations` and `acknowledged_incomplete_endpoint: receipt` keeps the supported
  coverage-limited receipt path explicit. A `structurally_unavailable_on_this_host` or
  `yoetz_limit_*` item remains a disclosed limitation the agent verifies itself; it does not become
  an impossible-to-do action, and it is never a blocker.
- Stable identity: a challenge whose kind matches a recorded AI-powered finding, whose subject
  set is exactly that finding's (the receipt's issue key), and none of whose subjects was recorded
  after that finding (the evidence fingerprint) is a restatement. A narrower or wider challenge is
  a distinct issue and is minted as its own finding, keeping its discrepancy and requested next
  step. It is "seen again, suppressed": no second row is
  minted, the check adds `semantic_restatements_suppressed` (tolerated by both proof classes, like
  the other dialogue disclosures), and the `semantic_review_accounting` diagnostic counts it as
  `semantic_restatements_suppressed` so returned = accepted + rejected + suppressed. Suppression
  never reads as absence: on an open item the check records a `still_present` ruling citing the
  restated subjects (at most 16), an explicit `fixed` or `withdrawn` ruling on the same item
  becomes `unassessable`, and an `acknowledged_not_done` or `rejection_accepted` item needs
  nothing recorded (it stays disclosed on the receipt). A `verified_resolved` row is never a
  restatement target: done stays done, and the problem raised again after that proof is a #458
  successor row, minted and blocking. When the check's 8-ruling bound is already full, the
  restatement is minted as before instead. A challenge that cites newer material is a new item,
  linked through `relates_to` when it cites the earlier finding.
- MCP text summaries count items by state with closed tokens only (`to-do: open N (M at budget
  B), verified V, not done A, rejection accepted R; next: <token>`); the CLI renders
  `[ ] F-1 fnd_… open (2/5)`, `[x]` verified, `[~]` not done, `[-]` rejection accepted, and one
  closed "Next:" sentence, plus a `Counts:` line from the check's whole-list counts and `Not
  listed: K` when the list leaves items out. The status findings summary counts actionable rows
  on the page only. The TUI `/findings` command reads the open task's `findings` status view
  with `include_resolved` and renders it through the same CLI lines, so every item shows its one
  state there too.

### Task statement (issue #908)

The reviewer judges the change against what the user asked for, kept apart from the agent's own
plan. Names and contracts:

- `start.task_statement` (optional in the unreleased start-request 1.1.0): the user's request as the agent
  transcribed it, 1..`MAX_TASK_STATEMENT_BYTES` (65,536) UTF-8 bytes. It is part of start request
  identity: a retry with the same `request_id` and statement replays; different words under the
  same `request_id` conflict. `finishup start --task-statement-file PATH|-` reads it verbatim. A
  request without it keeps its exact historical digest. A paused semantic-required check can
  receive the missing statement through a same-session `publish_work` plan amendment instead;
  that continuation preserves the original check identity and replays it after recomputation.
- Ledger: the unreleased `session_opened` 1.2.0 carries an optional `task_statement` beside the
  lineage metadata (on create; a statement alone selects 1.2.0, and a create with neither stays on
  1.1.0). The released families gain new versions that require it: `session_resumed` 1.2.0 (on
  reattach) and `plan_published`/`plan_revised` 1.1.0, which the unreleased event-draft 1.2.0 and
  publish-work-request 1.2.0 admit in place. Each released version stays frozen and never admits
  the field, and a version minted for the statement is never chosen without one. The advertised
  MCP `publish_work` presentation leaves the plan 1.1.0 branches out to hold the reviewed surface
  budget, while the CLI and service still accept plan branches for a same-session statement
  amendment. `domain/task_statement.current_task_statement`
  returns the newest readable statement in ledger order; earlier ones stay in history, and a
  redacted event contributes nothing.
- `DeterministicCase.task_statement` (`RecordedTaskStatement`) and `task_title` are frozen from
  the accepted prefix; the statement's source event joins `allowed_ids`, so it is citable. The
  frozen-case JSON gains a `task_context` key only when either is present.
- `TaskStatementSource`: `agent_transcribed` (every recorded statement), `host_captured_user_prompt`
  (reserved: no path records it and captured prompt text never enters a packet), and
  `task_title_only` (fallback).
- Packet: section `task_statement` (ordinal before `goal`), one item `task-statement`, category
  `task_description`, source kind `task`, content `yoetz.task-statement/1`
  (`source`, `statement`, `statement_bytes`, `elided_bytes`). Content is at most
  `MAX_TASK_STATEMENT_ITEM_BYTES` (16 KiB) of canonical JSON: a longer statement keeps its head and
  tail, marks `[... N bytes elided ...]`, and adds `semantic_case_content_over_item_limit`.
  `ReviewPacket.task_statement_item_ids` (max 1) and outbound-case 1.2.0 carry it. Catalog and
  provider rows for `goal` carry the fixed label `agent plan (the agent's own summary)`; the
  statement row carries its own fixed label. Plan payloads in the goal item and in timeline rows
  never include `task_statement`.
- Source order: agent statement, then task title (`task_title_only`), else no item. The item is
  built only when the effective review selection names `task_statement`. Composition builds from
  `review_selection_for_delivery(policy)`, which drops the section when the LLM channel withholds
  `task_description`, so a statement egress would filter is never offered and the packet names
  its absence.
- A `semantic_required` check whose metadata preflight is actionable returns `state:
  "awaiting_input"` with `semantic_reason: "review_input_required"` before repository or provider
  admission. Its continuation is a same-session `publish_work` plan publish or revision carrying
  `task_statement`; it retains the check's request identity and releases the observation barrier
  only for that correction path. Replay of the same check request recomputes deterministic
  assessments from the amended ledger frontier before semantic admission. This continuation is
  separate from `awaiting_human` privacy approval and never authorizes egress.
- Gaps (packet, check, finding baseline and receipt coverage): `task_statement_unavailable`
  (nothing carried) always travels with exactly one reason: `task_statement_not_authorized` (the
  selection lacks the section, or the LLM channel's `allowed_categories` lack `task_description`,
  whether or not a statement is recorded) or
  `task_statement_not_supplied` (the section is selected but neither a statement nor a readable
  title is recorded). A title standing in adds no gap; its `task_title_only` source label is the
  disclosure. Receipts add fixed prose for each code. Without those codes, a receipt whose
  applicable check completed an AI-powered review also names the source in its limitations
  section, read from the ledger prefix that check tested: `agent_transcribed` when a statement
  preceded it, `task_title_only` ("had at most the task title") when none did, and nothing when a
  statement-bearing event there is no longer readable. They are semantic-only for deterministic
  absence proof and join `SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS` for semantic findings. A
  finding that carries none of them and was raised before the ledger's first statement-capable
  event (`ReplayIndex.first_task_statement_sequence`: a statement-bearing schema version whose
  readable payload carries a statement, or whose payload is no longer readable) tolerates them
  on a later check, so an AI-powered finding recorded before the upgrade can still clear: the
  review that raised it had at most the task title (`task_title_only`), never the user's request.
- Privacy: review section `task_statement` in privacy-policy 1.2.0. `ReviewSelectionPolicy
  .for_profile(profile, preset_version="1.1.0"|"1.2.0")`; the 1.2.0 goal-aware, Assisted and
  Expanded presets include the section, Structural never does, Custom only when listed.
  `PrivacyPolicy` accepts any versioned preset of its profile. Wire encoding picks
  `review_selection_policy_schema_version` (1.1.0 unless a 1.2.0-only section is selected), so an
  approval made before the section keeps its bytes and digest; a 1.0.0/1.1.0 row that names the
  section is `privacy_policy_row_corrupt`.
- Statement-sourced obligations (ADR-032 amendment, TB4 pilot): an obligation maps the request
  when its `source_refs` names an event that recorded the current statement content.
  `RecordedTaskStatement.equivalent_event_ids` (from `current_task_statement`) lists every readable
  `session_opened|session_resumed|plan_published|plan_revised` event whose statement is
  byte-identical to the current one; the frozen case JSON carries the list only when it holds more
  than one id. An event that repeats the current statement byte for byte (a re-attach whose
  `task_statement` is unchanged, or a plan event restating it) is recorded but does not replace the
  current statement event, so the finding subject, specification revision and packet source ref do
  not move; an amended statement becomes current and must be mapped again.
  `kernel/plan_drift.task_statement_unmapped(projection, statement)` is the one predicate;
  `instruction_requirement_unmapped` is `agent_actionable` and is excluded from
  `PLAN_DRIFT_ADVISORY_GAPS`. `kernel/deterministic_checks.build_task_statement_unmapped_assessment`
  raises `task_requirement_unmet` (facts `task_statement_unmapped` /
  `statement_sourced_obligation_absent`, subject: the statement event) on whole-case checks only.
  `kernel/test_edit_visibility.preexisting_test_edits(..., task_statement_event_id=...)` accepts the
  equivalent ids and treats a test file listed as an `item_kind` `file` requested item of such an
  obligation as justified.
- Completion on an undecomposed request (pilot-blocker amendment): with a statement recorded and an
  effective completion claim, a readable plan chain with no plan or an explicit empty scope raises
  the same `task_requirement_unmet` identity with fact `task_statement_scope_empty` and summary
  `TASK_STATEMENT_SCOPE_EMPTY_SUMMARY` (`kernel/plan_drift.task_statement_scope_empty_at_completion`;
  it also adds `instruction_requirement_unmapped` to coverage). Mid-task checks before any completion
  claim never raise it. It is answered by statement-sourced obligations, or by a readable,
  unsuperseded `decision_recorded` whose statement holds the exact line
  `finishup-no-material-work:<statement event id>` (any equivalent id; `NO_MATERIAL_WORK_MARKER`);
  that decision is contradicted, and does not count, while the projection holds any `edit` action
  or the check-time change capture (`CheckChangeMetadata`) shows any changed path. Shell writes are
  recorded as command actions, so the capture is the witness; a check without that capture does not
  honour the decision (fail closed). `application/check.py` passes `workspace_changed` to
  `build_task_statement_unmapped_assessment`; the ledger-only drift advisory keeps the edit rule.
- Both research-evidence `task_requirement_unmet` rules (statement and test edit) are emitted only by
  a check whose research-evidence execution is `run/completed`, the same condition their
  resolution requires. A recorded statement is a research-evidence root, so the pack runs before
  the first claim. The test-edit finding adds fact `task_statement_recorded` (the statement event)
  when a statement is recorded, and its text spells out the complete repair: a new statement-sourced
  obligation listing the test path as a `file` item, `plan_revised` carrying it, an `edit` action
  whose `attempted_items` list the path (with its result), a verification rerun after that action,
  the resolved obligation citing that fresh observed evidence, and a superseding claim naming it.
- Path-metadata test-edit captures carry no diff body: an edited pre-existing test whose skip
  marker cannot be read is `preexisting_test_skip_unknown` (standing; not informational, so the
  check stays coverage-incomplete) rather than `preexisting_test_baseline_unknown`, which now means
  only an unknown task-start baseline or an omitted/truncated edit set.
- Observed corroboration (same amendment): work-integrity `claim_without_admissible_evidence` with
  facts `observed_verification_uncited` / `observed_verification_absent` (subject: the completion
  claim) fires when hooks observed an edit or a verification run with a recorded outcome and the
  claim's support chain cites no verification-class material after the latest hook-observed edit:
  a hook-observed, non-`exploration`/`vcs` command result (an outcome-less result counts for
  corroboration but never triggers the rule) or captured output such a result links, at that
  result's frontier. Standalone captures, an edit's output and exploration or VCS output never
  corroborate. Self-generated evidence stays admissible (#977 item 5, ADR-033; tb4n1 E7, #987):
  the agent's own admissible `command` result outside the `exploration`/`vcs` runner classes (a
  disclosed failing one included) or
  `test_result`/`command_output` evidence published after the latest hook-observed edit also
  satisfies the rule.
- The unreleased local control 2.9.0 carries the fields in place and admits either
  privacy-policy wire version. A newer client meets an older running service at the schema-manifest
  digest in `control-hello` (`manifest_mismatch`, superseded through `finishup service restart`), and a
  released 0.2.5 boundary's closed start-request 1.0.0 schema refuses the field rather than
  dropping it.
- Golden vectors: `fixtures/canonical/task-statement.case.json` (TSK-001, owned by
  `scripts/generate_task_statement_fixture.py` through the resource ripple) pins every
  statement-bearing event version beside its frozen predecessor, the statement-free start request
  digest (equal to the digest before the field existed) and the privacy-policy 1.1.0 and 1.2.0
  wires of one approval.
- `TASK_STATEMENT_REVIEW_INSTRUCTION` (appended to the Responses and Chat Completions system
  instructions): the task statement is the specification and wins over the plan; an omitted or
  contradicted stated requirement is a discrepancy citing the statement's source ref; never request
  behaviour it excludes; weigh `agent_transcribed` as the agent's account.

### Excerpt count (issue #907 Phase 1b)

- `MAX_REVIEW_EXCERPTS` (`protocol/models.py`) is 64, a protocol maximum. It bounds
  `ReviewPacket.targeted_excerpts`, `ReviewSelectionPolicy.max_excerpts` and outbound-case 1.2.0
  `targeted_excerpts`. `PRE_1_2_MAX_EXCERPTS` (`domain/privacy.py`, 16) is the bound of wire
  1.0.0/1.1.0.
- `ReviewSelectionPolicy.for_profile(EXPANDED, preset_version="1.2.0")` sets `max_excerpts` to 64.
  The 1.1.0 Expanded preset and both Assisted presets keep 16. Every preset keeps 16,384 bytes per
  excerpt and 131,072 bytes in total.
- `review_selection_policy_schema_version` returns 1.2.0 when a selection names `task_statement`
  or sets `max_excerpts` above 16, and 1.1.0 otherwise. A 1.0.0/1.1.0 row that decodes to more
  than 16 excerpts is `privacy_policy_row_corrupt`.
- Privacy-policy 1.2.0 (unreleased, edited in place) bounds `max_excerpts` by 64 and pins the
  Expanded preset's `max_excerpts` const at 64. The released 1.1.0 schema is unchanged.
- Egress (`application/egress.py`): after minimization and the channel ceilings, a
  `semantic-review` payload is `blocked_by_policy` / `policy_denied` when its `excerpt` rows exceed
  the effective `max_excerpts`, any row exceeds `max_excerpt_bytes`, or their sum exceeds
  `max_total_excerpt_bytes`. An unreadable payload is refused the same way.
- The case item bound `_MAX_CASE_ITEMS` (`ports/semantic.py`) is `256 + MAX_REVIEW_EXCERPTS - 16`
  (304), and outbound-case 1.2.0 `content_items` allows 305.
- The `semantic_case_built` counters add `semantic_excerpt_count_approved` and
  `semantic_excerpt_byte_approved` (the owner-approved selection),
  `semantic_excerpt_count_cut_for_case_bound` (excerpts dropped to fit
  `MAX_SEMANTIC_CASE_BYTES` before ceiling planning), `semantic_excerpt_count_limit` and `semantic_excerpt_byte_limit` (the effective limits the case
  was built with after ceiling planning) and `semantic_excerpt_ceiling_rounds`. All precede privacy
  minimization and certify neither consent nor delivery.
- `build_semantic_case` drops the lowest-ranked excerpts, as `not_selected` omissions with
  `content_unselected`, when the case would otherwise exceed `MAX_SEMANTIC_CASE_BYTES`; a case
  within that bound is unchanged. The count is `SemanticCase.excerpts_cut_for_case_bound`, local
  composition state outside the envelope and digest. When non-excerpt items alone exceed the
  bound it raises `SemanticCaseCapacityExceeded` (the base of `LineageSemanticCapacityExceeded`),
  reported as `case_capacity_exceeded` with operation `semantic_not_dispatched_case_capacity`.
- `service/semantic_ceiling.py`: `channel_prepared_limit(policy)` is the narrowest of the LLM
  channel's `max_bytes`, `max_tokens × 4` (zero is unset) and `MAX_MINIMIZED_DISCLOSURE_BYTES`
  (`ports/privacy.py`, 262,144), so an unset or high ceiling still plans below what egress can
  prepare. `channel_admission(policy, bindings)` is the categories and data classes egress
  releases to those destinations (LLM channel ceiling for external, local-model ceiling for
  `local_af_unix`, unioned), with each item's data class from the enforcer's
  `clean_item_data_class`. `plan_under_channel_ceiling` measures only the items that admission
  releases, and rebuilds
  an over-ceiling case with a smaller `max_total_excerpt_bytes` (and `max_excerpt_bytes`), or no
  excerpts. It stops after at most `MAX_CEILING_PLANNING_ROUNDS` (4) rebuilds, and every rebuild
  adds `content_unselected`. It is deterministic, so a recovered case keeps its digest.
- Resume (`PrivacyCoordinator._resume_admitted`) denies a stored `semantic-review` proposal,
  external or local-model, outside the current policy's excerpt limits or LLM `max_bytes` /
  `max_tokens` with `blocked_by_policy` / `policy_denied` before dispatch.
- TUI: `PrivacyPosture.recipe_outdated` is true when the approved selection is an earlier version
  of its recipe. The privacy screen then offers the newer recipe instead of saying "already on the
  recommended privacy policy".
- CLI: `policy_excerpt_limits_disclosure` renders the approved limits and, when the current recipe
  for the profile differs, the proposed ones. `finishup privacy show` on a terminal prints it as
  "Excerpt limits: …". `finishup --privacy` prints "Current excerpt limits: …" and the draft's
  "Maximum: …". The ceremony adds fixed words to a `max_excerpts` change.
- Golden vectors: TSK-001's privacy-policy wire now also pins the PRIV-004 Expanded policy under
  both presets: 1.1.0 with 16 excerpts, byte-identical to origin/0.3, and 1.2.0 with 64.

### Check-time change (ADR-031, #883)

`ChangeCapturePort` (`finishup.ports.change_capture`) has two blocking, read-only calls:
`read_task_base(workspace) -> TaskChangeBase` and `capture(workspace, base | None) ->
CheckChangeCapture`. `GitChangeCaptureAdapter` is the only implementation; the service runs it and
every redaction pass off the event loop. One 20-second deadline bounds a capture: each Git call
(including workspace discovery and the global `core.excludesFile` read) gets `min(10 s, time left)`.
Assembly may use the first 75% (`_ASSEMBLY_SHARE`); the rest is kept for the closing stability
check. Past the assembly share a file whose diff was not read is listed with `capture_limit` and
untracked files are not listed; before the file list exists, or during the stability check, the
capture is unavailable. `_open` first reads the system Git's version (`finishup.adapters.git_version`,
cached per executable identity); a known version older than 2.25 is `git_version_unsupported`.
Before any diff the adapter lists the effective config with `git config --list --name-only
--includes --show-origin -z` and refuses any key not of origin `command line:` (the runner's own
`-c` values) that is `filter.*`, `include.*`, `includeIf.*`, `extensions.partialClone`,
`remote.*.promisor` or `remote.*.partialCloneFilter` (`unsupported_repository`); a Git that cannot
list it fails closed before any diff; an effective `core.worktree` is `unsupported_repository`
too. The repository-level `core.excludesFile` is the last non-command-line value of `git config
--get-all --show-origin -z core.excludesFile`. `discover_workspace_root` runs `rev-parse
--show-toplevel --absolute-git-dir` and raises `unsafe_root` unless the git dir is `<top>/.git` and
the candidate lies inside `<top>`. Every capture Git call runs as `git --no-replace-objects -c
core.quotePath=true -c diff.relative=false -c protocol.allow=never --git-dir=<root>/.git
--work-tree=<root> ...` through `run_read_only_git` (whose environment is a fixed dict with `HOME`
and `XDG_CONFIG_HOME` set to `os.devnull`, so no `GIT_*` variable is inherited and no global
configuration is read even on a Git before 2.32, which ignores `GIT_CONFIG_GLOBAL`); `_open`
requires that invocation's `rev-parse --show-toplevel --absolute-git-dir` to print exactly
`<root>` and `<root>/.git` once canonicalised. `_rev` passes `rev-parse --verify --quiet <spec>`
and refuses a spec that is empty or starts with `-` before Git runs (no `--end-of-options`, which
`rev-parse` learned only in Git 2.30). No argument needs a Git newer than 2.25 (ADR-031, #1040
amendment).
Before and after each call the root pathname and its `.git` must still `lstat` to the device and
inode recorded from the validated descriptor (`unsafe_root` otherwise).
`_refuse_unsafe_object_store` requires `.git/objects`, `objects/info` and `objects/pack` to be real
directories of the service user and each fan-out directory a real directory, and every
pack-directory entry a regular file of the service user that no other account can write (ADR-007, 2026-10-14: group write through the owner's private group is owner-only; any link
count; a link or a foreign-owned or writable entry is `unsafe_root`, more than 4096 entries
`unsupported_repository`); `objects/info/alternates` and `objects/info/http-alternates` are
`unsafe_root`, as the ADR-011 open fence already makes static alternates, and `.git/commondir` is
`unsupported_repository`. It returns the identities of the object directories, fan-out directories
and pack entries, taken at the start of each attempt and compared by the closing check. The tracked
list is `git diff --raw -z --no-abbrev <base> --`, which reads no file or blob content; immediately
after it, before `--numstat`, the patch or verification, the adapter records the no-follow identity
of each changed working copy and of each loose blob path (and its fan-out directory) the diff names.
Each changed working copy must be a regular, single-link file of the service user unless the entry
is a deletion or a submodule, otherwise it is omitted as `not_regular_file` with its line counts
(Git's output for it is discarded). Every blob a shown section reads (`src`, and a non-zero `dst`,
of mode 100644, 100755 or 120000) is verified: a loose object must be a regular, owner-only file
(any link count) whose descriptor still has the recorded identity before and after it is read, and
is inflated (`zlib`) and hashed from that descriptor; the blob is also read with `git cat-file blob`
(at most 8 MiB each, 64 MiB in all) and hashed. Either mismatch omits the section as
`object_unverified` (or `too_large` / `capture_limit` at the bounds), line counts withheld. The
adapter overwrites the compressed and inflated buffers it owns. Tracked and untracked files whose
base name is on the adapter's credential-name list are listed by name only (`credential_name`). The
untracked listing uses `run_read_only_git(..., keep_prefix_on_limit=True)`: past 8 MiB the hardened
runner raises `GitOutputTruncated` (still a `ValueError("git_output_limit")`) holding the whole
names that fit, and the header says the untracked count is a lower bound. Each untracked file read
must still have the identity its path had just before (mode, device, inode, size, mtime and ctime in
ns, link count, owner) when opened and after it is read, with exactly `st_size` bytes read. The
closing stability check re-reads the object-store snapshot, the raw tracked list, every recorded
working-copy, loose-object and untracked identity, the untracked listing, `HEAD^{commit}` and the
identity of `.git/index`; any difference retakes the whole capture, at most `_CAPTURE_ATTEMPTS` (3)
times while the assembly share lasts. `discover_workspace_root` and `open_local_workspace` take an
optional `timeout_seconds`. `ChangeCaptureUnavailable.reason` is one of `git_unavailable`,
`git_version_unsupported`, `not_git`, `unsafe_root`, `unsupported_repository`, `git_failed` (a Git call over its time bound
included), `changed_during_capture` (the working tree moved during every attempt) or
`redaction_incomplete` (credential-shaped spans still found after 64 redaction passes, so the change
is withheld whole), recorded as a bounded `semantic_composition/check_time_change_unavailable` (or
`start/task_change_base_unavailable`) diagnostic and never as text.

- **Base.** A `start` whose outcome is `created` or `delegated` records
  `TaskChangeBase(object_format, commit)` (the empty tree for an unborn repository) as an encrypted
  `change_capture` object of media type `application/vnd.yoetz.task-change-base+json`, schema
  `yoetz.task-change-base/1`. A `task_start` base also carries the task-start snapshot of the
  ADR-031 #1045 amendment as optional canonical-JSON keys: `untracked` (`[[path, state], ...]`,
  each an `UntrackedBaselineFile`), `untracked_complete`, `nested` (`[[directory, commit], ...]`)
  and `nested_untracked` (`[[directory, complete, [[path, state], ...]], ...]`, each a
  `NestedUntrackedBaseline` for a `nested` directory, rows and paths in ascending order, written
  only when non-empty; an incomplete row names no file). Every listed file counts against one
  4096-name, 256 KiB bound; a base without these keys keeps its bytes and reads as no snapshot.
  `decode_task_change_base` accepts only what the encoder writes (the three snapshot keys together
  and not all empty, `nested_untracked` only beside them, never empty or null) and rejects any other
  shape; a `first_check` pin carries none. The
  optional ledger seam `record_task_change_base(ref) -> bool` keeps
  the first one only (pointer in `bundle_meta` key `task_change_base`, object inventoried as a
  root); `load_task_change_base()` authenticates it. Attach and resume record nothing. A task with
  no base gets one from its first check that captures a change: `TaskChangeBase(...,
  origin="first_check")`, HEAD at that check, recorded through the same seam (a concurrent check
  that loses the race loads the kept one).
- **Source.** `Application.check` binds `CheckWorkspaceSource(workspace, repository_commitment)`
  from its own `RepositoryPrivacyContext` for the duration of the check
  (`check_workspace_source_scope`). The semantic composition captures only when that commitment
  equals the task route's, and only for a new durable job whose recipe selects diff excerpts.
- **Object.** `CheckChangeCapture(base, text, tracked_files, untracked_files, omitted_files,
  truncated, redacted)` is stored after capture-time redaction as one `change_capture` object of
  media type `application/vnd.yoetz.check-change+json`, schema `yoetz.check-change/1`. `base` is
  `task_start`, `first_check` (the pinned first-check base; the header names its commit),
  `head` (no base could be kept or resolved) or `empty` (no commit exists); `first_check` and
  `head` report `check_time_change_base_unavailable`. The job's
  `yoetz.semantic-case/2` object gains an optional `check_change` member,
  `{"schema": "yoetz.check-change-binding/1", "object": pointer | null, "unavailable": bool}`
  plus, for an unavailable change, an optional `"reason"` (one of the closed reasons below);
  jobs without it rebuild without a change.
- **Packet.** `build_semantic_case(check_time_change=CheckTimeChange(ref, capture) | None,
  check_time_change_unavailable=bool, check_time_change_unavailable_reason=str | None)` admits
  parts with ids `change-check-time-NNN`, section `excerpt`, category `repository_excerpt`, source
  kind `diff`, source ref `check-time-change`, linked to effective claims and obligations (else the
  latest plan), each prefixed `[FinishUP check-time change, part i of n]`. A current-file section
  an in-check follow-up serves uses the same synthetic source ref. An omission row cannot name
  that token: when count, byte or aggregate case bounds drop the excerpt, the omission names each
  valid linked ledger subject (category and reason unchanged) and `content_unselected` stays set.
  A linked token that is not a ledger subject is skipped; subject validation is not relaxed
  (issue #1077). A verification-output follow-up may also carry hook-captured output of the newest
  run of a command the request names, as a `repository_excerpt` labelled observed, only when that
  recipe already sends repository excerpts and only inside the existing byte limits. Private sends
  nothing. A follow-up packet that adds no new part is not sent, so the completed
  `insufficient_packet` review stands. Each part is at most
  `min(max_excerpt_bytes, max_total_excerpt_bytes, item bound)` bytes, marker included (16 KiB
  under Expanded; issue #983). `_check_time_change_reservation(selection, first_part_bytes)`
  returns the share admitted before other excerpts (half the excerpt count, at least one, and half
  the total bytes rounded up to the first part). Leftover parts take the room the reserved excerpt
  ranks (current diff, latest verification, prior-finding context) leave, ahead of older edit
  hunks and unreserved or superseded excerpts; any still left backfill after every other excerpt.
  When a narrowed case leaves less room than one whole part, the first part is cut to that room
  (at least 256 change bytes, on a line end where one lies in its second half) and prefixed
  `[FinishUP check-time change, part 1 of n, cut to the packet's room]`; nothing follows it and
  `check_time_change_truncated` is disclosed (issue #983).
  When that budget cannot hold the whole change and the files are not all the same kind, sections
  that change a decision are admitted before boilerplate (comments, imports, license or
  copyright comment and header lines). A decision line counts even when it names a license. The
  decision's own section is still a run from its start. A one-file change, equal-rank files, and
  a change that fits stay a leading prefix. The first reordered part carries one fixed line that
  decision-changing sections were shown ahead of boilerplate and that sections which did not fit
  were not shown; it names no path. Leading bytes stay the contiguous prefix from byte 0.
  Intervals outside that prefix are returned with the served sections
  (`check_time_change_sections_carried`), so the shown-file record names those files and not the
  ones left out (issue #1079).
  Untracked files are read up to `MAX_CHECK_CHANGE_TEXT_BYTES` less the header budget (232 KiB). The case digest binds the object
  identity, content digest, base, flags, admitted part count and any unavailability reason; a case
  without a selected change keeps its historical digest input.
- **Unavailability reasons.** `CheckChangeOutcome.reason` and the builder's reason are keys of
  `finishup.domain.receipts.CHECK_TIME_CHANGE_UNAVAILABLE_REASONS` (`git_unavailable`,
  `git_version_unsupported`, `not_git`,
  `unsafe_root`, `unsupported_repository`, `git_failed`, `changed_during_capture`,
  `redaction_incomplete`, `repository_mismatch`, `capture_failed`, `no_linked_subject`,
  `no_packet_room`); every `ChangeCaptureUnavailable` reason is one of them.
  `check_time_change_unavailable_reason_gap(reason)` gives the coverage code
  `check_time_change_unavailable_<reason>`, recorded beside `check_time_change_unavailable` in
  `known_gaps` (no schema change: gap codes are closed tokens) and a member of
  `CHECK_TIME_CHANGE_GAPS`, so finding resolution treats it as a check-time limit.
  `check_time_change_gap_sentence(code)` returns its one fixed sentence, which the receipt builder
  puts in the gap's `detail` and the limitations section body (so JSON, markdown and text receipts
  carry it), `render_human_check` and `render_human_status` print after the gap list, and the MCP
  check summary appends when it fits the bound.
- **Shown files.** `check_time_change_shown_files(capture, shown_bytes)` returns each
  `diff --git` section of the stored change that reached its leading `shown_bytes`, whether it arrived
  whole and without a `[REDACTED]` marker, the section bytes that arrived, the markers among them,
  whether the whole section arrived, and where the first shown marker starts. The identity is the
  section's first line plus `\0binary` for a `Binary files ` line and `\0deleted` for a `deleted
  file mode ` line. `shown_bytes` is `check_time_change_bytes_carried(case,
  withheld_categories=)`: the change bytes (marker lines excluded) of
  `check_time_change_parts_carried(case, withheld_categories=)`, the unbroken run of parts from the
  first whose catalog rows `bounded_case_envelope(case)` kept, or 0 when the policy withholds
  `repository_excerpt`. Counting bytes keeps the record exact whatever part size a planned
  selection chose and when the first part was cut (issue #983).
  `check_change_shown_files(runtime, change, shown_bytes)` commits each through
  `runtime.objects.commitment_for(..., CHANGE_CAPTURE)` over the domain
  `yoetz/check-change-shown-file/v1`, the base commit and that identity. Each partially shown file
  also gets `view_commitment`, the same key over `yoetz/check-change-shown-view/v1`, the base
  commit, the identity and `CheckTimeChangeShownFile.view`: the length-prefixed shown length, the
  whole-section flag, every marker offset, and every hunk's offset and header line within the shown
  bytes. The view is never stored; it is derived from the same `shown_bytes`, so envelope
  minimization cannot desynchronize it from the accounting. `CheckChangeCapture` and
  `yoetz.check-change/1` carry `base_commit`. The composition passes it to
  `FinalSemanticEvaluation.check_change_files`, and `commit_check_if_current(...,
  check_change_files=)` records it only beside a conclusion.
  Tight selections may serve interior decision-bearing hunk intervals ahead of a file's
  boilerplate, with original file/hunk headers and skipped byte intervals labeled. Original
  spans, excluding those synthetic labels, drive the shown record. Interior/disjoint views
  use `yoetz/check-change-interval-view/v1`, relative interval endpoints and length-prefixed
  structural views; only their keyed commitment is durable. Their `shown_bytes` counts the
  union, and the view also binds any preceding original hunk header repeated as context.
  These views have `clean_bytes=0` and `section_admitted=false`; an identical view or a whole-file
  review covers them. Leading views retain their historical representation (ADR-031, F3).
- **Consent.** `ReviewSelectionPolicy.carries_check_time_change` (targeted excerpts, a positive
  excerpt count and the `diff` kind) is the one predicate for whether a recipe carries the change,
  and `required_categories()` then includes `repository_excerpt`. An inference channel without that
  category approves no check-time part, and `withheld_review_categories` names it, so the check
  reports `semantic_review_context_withheld`.

### Task facts, blocker decisions and the Stop-time closure gate (issue #977, ADR-033)

- **`kernel/task_facts.py`.** `task_fact_signals(projection, records) -> TaskFactSignals(codes,
  markers, acting_started, blocked)` derives closed codes from service-stamped hook observations and
  the effective plan. `markers` pair a code with its obligation (`<code>:<obligation id>` in the
  frozen case) or `None`. Agent-actionable (`AGENT_ACTIONABLE_TASK_FACT_GAPS`):
  `planned_verification_not_observed`, `planned_verification_failed`,
  `planned_verification_stale`, `edited_after_last_verification`, `requested_output_git_ignored`,
  `declared_output_removed` (ADR-035), `declared_output_emptied` (ADR-035 amendment, ADR-041),
  `deliverable_references_undeclared_file` (ADR-035 amendments, #1022, agent work since #1044). Standing (`STANDING_TASK_FACT_GAPS`): `planned_verification_outcome_unknown`,
  `planned_verification_unobservable`, `planned_verification_agent_linked`,
  `planned_verification_matched_by_prefix` (ADR-045: a prefix or flags match, counts as run),
  `declared_output_not_reviewable` (ADR-045), `install_into_yoetz_runtime`, `install_into_private_env`,
  `write_outside_workspace`, `verification_only_as_root`,
  `obligation_blocked_outside_agent_control`, `requested_output_ignored_by_repository`,
  `declared_output_content_moved` (ADR-035),
  `deliverable_references_ambiguous_name` (tb4n5, ADR-035: counted, never named; gap rule G4b),
  `requested_output_unchanged`,
  `requested_output_outside_workspace`, `requested_output_unverified`. Each code is classified
  once in `GAP_CLASSIFICATION`; standing ones are advisory for the check verdict, the receipt
  conclusion and `DETERMINISTIC_SCOPED_STANDING_GAPS` (all through
  `kernel.deterministic_scope.CLEAN_COMPATIBLE_GAPS`, #986), and every task-fact code is tolerated
  by a local absence proof; the environment facts `write_outside_workspace`,
  `obligation_blocked_outside_agent_control` (issue #1000), `verification_only_as_root`,
  `install_into_private_env`, `install_into_yoetz_runtime` and the planned-verification observer
  heuristics `planned_verification_agent_linked`, `planned_verification_matched_by_prefix`,
  `planned_verification_outcome_unknown`, `planned_verification_unobservable` (issue #1046) are also
  tolerated by an AI-powered absence proof under an explicit, admitted `fixed` ruling on that
  finding (admission already requires the ruling to cite evidence or a result recorded after the
  finding), never when the review is silent on it. They stay on the receipt; the resolved finding's
  explanation names the ones its resolving check carried. Facts about the deliverable
  (`requested_output_*`, `declared_output_*`, `deliverable_references_undeclared_file`) and every
  agent-actionable fact keep blocking it. `build_deterministic_case` and the compact status gaps add them beside the
  plan-drift signals.
- **Planned-verification identity.** `register_command_identity_key(key)` (the service calls it at
  composition with the local observation store key) lets `requested_command_identity(value)`
  compute `hmac-sha256:` over `normalize_observed_command(value)`, the identity a hook records as
  `omitted:<commitment>`. Without a registered key no planned-verification code is produced.
  `requested_command_identities(value) -> (whole, segment identities, composition) | None` adds the planned
  value's own segment commitments. An agent link (ADR-033 decision 1, #1003) also matches: a
  cooperative `command` action whose `attempted_items` holds the exact value and whose
  `causal_parents` names a hook-observed command action, attributed per obligation; the observed
  run's outcome decides, and an item matched only that way adds the standing
  `planned_verification_agent_linked` (`PLANNED_VERIFICATION_AGENT_LINKED_GAP`).
- **Command segments (`domain/command_segments.py`, ADR-033 decision 1).**
  `command_segments(normalized) -> CommandSegments(segments, composition) | None` splits a
  normalized command into its simple commands (quote-aware; `None` when unsplittable or already
  simple); `command_segment_commitments(key, normalized) -> (sorted commitments, composition) |
  None` keys them, excludes the whole commitment and keeps at most `MAX_SEGMENT_COMMITMENTS` (32:
  first and last 16 distinct in command order). `COMMAND_COMPOSITIONS` = `single`, `and_chain`,
  `masked`. `requested_command_shape(value) -> "command" | "placeholder" | "prose"`. Hooks put
  the result on the structural fields `command_segment_commitments` and `command_composition`
  (control-request 2.9.0, hook spool, Codex session stream);
  `kernel.observed_failures.observed_command_field(commitment, segments, composition)` writes the
  action `command` field (`omitted:<identity>` unchanged for a simple command, else
  `omitted:<identity> <composition> <segment>...`), `command_identity` reads only the leading
  identity, and `command_segment_identities(command)` reads the suffix or returns `None`.
- **Placeholder refusal.** `publish_work` refuses an `obligation_published` `command` item whose
  value holds an unquoted `<name>` token with `EVENT_INVALID`, reason
  `requested_command_placeholder`, field `/event_drafts/N/payload/requested_items/K/value`, and a
  fixed corrective message; the trusted import channel is exempt.
- **`acting_started(projection, observed, cooperative)`.** True after an observed edit, an observed
  run whose runner class is `test`, `lint`, `typecheck` or `build`, or any cooperative (MCP or local
  CLI) action. `cooperative_event_ids_from_records(records)` and `observed_event_ids_from_records`
  supply the two sets.
- **Blocker decisions (claimed, then confirmed; #985).** `blocker_declarations(projection,
  batches) -> Mapping[ObligationId, BlockerDeclaration(kind, decision_event_id,
  confirmation_event_id)]` reads readable, unsuperseded `decision_recorded` events whose statement
  holds the exact line `finishup-blocker:<kind>` (`BLOCKER_MARKER`; `BLOCKER_KINDS` = `authority`,
  `consent`, `credential`, `dependency_unavailable`) for their `affected_obligation_ids`. The
  earliest decision in ledger order *claims* the obligation; the earliest later decision repeating
  the same kind for it in a different publish batch (`decision_batches(records)`: decision event id
  to its `operation_id`) *confirms* it. A repeat in the same batch, two lines in one decision, or a
  dry run never confirms; without batches nothing confirms. A later decision of another kind
  starts a new claim of that kind; superseded decisions count in neither role.
  `blocked_obligations(projection,
  batches)` returns confirmed blockers only; case-only readers (work-integrity,
  the check-time output read) use `confirmed_blocked_obligation_ids(case gaps)`, which reads the
  frozen `obligation_blocked_outside_agent_control:<obligation>` markers. Only a confirmed blocker
  suppresses planned-verification facts, requested-output facts and `requested_item_never_attempted`.
  Task facts emit `obligation_blocked_outside_agent_control` (standing) for a confirmed open
  obligation and the agent-actionable Stop-gate token `obligation_blocker_unconfirmed`
  (`OBLIGATION_BLOCKER_UNCONFIRMED_GAP`) for a claimed one. `ClosureReadinessFacts` carries
  `open_obligation_ids`, `blocked_obligation_ids`, `blocked_obligation_details` (`(obligation,
  kind, decision event id)`) and `blocked_obligation_confirmations` (`(obligation, confirming
  event id)`). When every open effective obligation is blocked, `derive_closure_readiness`
  replaces `obligations_open` with `obligation_blocker_unconfirmed` (agent-actionable) while any is
  only claimed, and adds the standing `obligation_blocked_outside_agent_control` for confirmed
  ones; when all are confirmed, `completion_plan_not_claimed` also moves to standing.
  `StatusClosureReadinessModel` admits exactly those shapes. Status `closure_readiness` carries
  the optional `blocked_obligations` list (`obligation_id`, `blocker_kind`, `decision_event_id`,
  `confirmation` `claimed|confirmed`, and `confirmation_event_id` exactly when confirmed; at most
  64, ids and closed tokens only, absent from an earlier 0.3 build), and the CLI/terminal status
  renders it as "Recorded blockers (agent-declared, unverified)". F3 (ADR-025 decision 8):
  `ClosureReadinessFacts.limitation_refs_required` is
  `kernel.claim_limitations.required_limitation_ids_for_projection` (the reducer's own rule for a
  whole-task claim). Status `closure_readiness` carries the optional pair
  `limitation_refs_required` (sorted `res_` ids, at most 64) and `limitation_refs_required_count`,
  which are present together. The MCP status summary, the CLI/terminal status and the Stop gate
  name them; the gate names at most 5. Standing task facts never become
  `ledger_stale_or_incomplete` findings.
- **Publish-time blocker notices (#985 C2b/C3).** `publish_work` success and dry-run results
  (publish-work-result 1.1.0) carry optional `blocker_notices` (1..64 rows: `obligation_id`,
  `blocker_kind`, `notice` `blocker_claimed|blocker_confirmed|blocker_without_effect`, and `text`,
  the fixed `PUBLISH_BLOCKER_NOTICE_TEXTS[notice]`), one per `(obligation, kind)` of the batch's
  blocker lines, from `task_facts.blocker_publication_notices(projection_with_batch,
  ((event_id, payload), ...))`. `blocker_claimed` is the challenge (repair first; a FinishUP limit is
  never a blocker, respond `self_verified`; recoverable data is not a blocker; only if still
  genuine, confirm by repeating the line in a later publish with a rationale that names what was
  re-checked, since an unchanged id-less resend is refused as a possible retry) and, with the Stop
  re-check, the only text that says how to confirm. `blocker_without_effect` marks a blocker naming no open
  obligation, including an id the task does not know: it changes no readiness, gap or finding (use `self_verified`, or
  `acknowledged_not_done` as a last resort). `mcp.summaries.render_publish_blocker_notices`
  renders the rows on the MCP text channel; structural pointers admit the four leaves.
- **Publish-time action notices (tb4n5 follow-up).** `publish_work` success and dry-run results
  (publish-work-result 1.1.0, unreleased, changed in place) carry optional `action_notices`
  (1..100 rows, the batch bound, so a full batch is never cut: `action_id`, `notice`
  `result_not_linked`, and `text`, the fixed
  `PUBLISH_ACTION_NOTICE_TEXTS[notice]`), one per action the batch recorded that no
  `result_recorded` names at the batch's own frontier (`publish_work._action_notices`), absent
  otherwise. It records nothing and changes no finding: it states the pairing rule (a result whose
  `action_id` names the action, normally in the same batch; evidence, decisions and causal parents
  link nothing) before a later batch's unrelated work raises `action_without_result`.
  `mcp.summaries.render_publish_action_notices` renders the rows on the MCP text channel;
  structural pointers admit the three leaves (result leaf registry 1614). Golden vectors: fixture
  `CAN-018` (`fixtures/canonical/publish-action-notices-1.1.0.case.json`, owned by
  `scripts/generate_publish_action_notices_fixture.py` through the resource ripple).
- **Closing review of blockers (#976, #978).** `semantic_case.recorded_blockers(projection)`
  returns `(decision event id, kind, open obligation ids)` per blocker decision on open
  obligations, claimed or confirmed, and `review_question_set(phase, blockers)` adds one
  final-phase question that lists them (at most 16, ids and closed kinds) followed by
  `BLOCKER_REVIEW_INSTRUCTION`: quote the blocked obligation's description and evidence expectation
  from its packet item `obligation-<id>`, then challenge (required) when the statement says the
  outcome is achievable or the data recoverable, the obvious prerequisite was not attempted, the
  material contradicts it, or it names a FinishUP/review limit; the main deliverable calls for
  scrutiny only, and a genuine credential or authority blocker on it may stand.
  That challenge becomes an ordinary AI-powered finding. Blocker decisions lead the decision
  section, and their statement and rationale, like the obligation text, travel only as
  privacy-gated packet items. Golden question:
  `tests/fixtures/tb4_replay/pretrain_blocker_review_question.json`.
- **Requested outputs.** `ChangeCapturePort` implementations may offer
  `probe_requested_paths(workspace, values) -> tuple[RequestedPathProbe, ...]`
  (`ports/change_capture.py`; `location` `inside|outside`, root-relative `relative`, `exists`,
  `ignored`, and for an ignored path `ignore_source` `info_exclude|repository_file|
  outside_repository` with the root-relative `ignore_file`), metadata only. `application/check_change.requested_output_states(...)` turns them,
  with the structural change capture, into `RequestedOutputState(location, exists, ignored,
  changed, deleted, ignored_by_task)` per `(obligation, item index)` (`ignored_by_task`: the rule is
  `.git/info/exclude` or a `.gitignore` the check-time change adds; values with whitespace, glob,
  brace, `~`, `$` or a URL scheme are not read), and `requested_output_facts(projection,
  states)` returns `(absent, markers)`; `requested_output_unchanged` and
  `requested_output_outside_workspace` are marked only for an item an `edit` action's
  `attempted_items` names exactly (`attempted_items_for_obligation(state, obligation,
  action_kind=ActionKind.EDIT)`), since a `file` item may name a read-only input. `work_integrity_findings(case, *, absent_outputs=)`
  raises `requested_item_never_attempted` with the fact `requested_output_absent`
  (`REQUESTED_OUTPUT_ABSENT_FACT`) for each absent pair that
  `reportable_absent_outputs(case, absent)` keeps: an effective completion claim covers its
  obligation (names it or names none), or `acting_started` and one of the agent's own (cooperative)
  `edit`, `command` or `other` actions is attributed to it. A requested
  directory is `changed` when any changed path lies beneath it; the root probes as `relative`
  `.`, inside, and is changed by any change.
- **Declared delivered set (ADR-035, issue #1005).** `kernel/delivered_set.py`:
  `declared_delivered_items(projection) -> tuple[(obligation, item index, item kind, value), ...]`
  is every effective, unblocked obligation's requested item of kind `file` or `directory` whose
  `role` is `output` (a role-less 1.0.0 item never counts). `declared_output_removed(projection,
  states) -> tuple[ObligationId, ...]` names the obligations whose declared item has an `inside`
  `RequestedOutputState` with `exists=False` and either `deleted=True` (deleted, or renamed away,
  by the check-time change) or an `edit` action of the session naming it (written, then moved). `_requested_output_inputs` in `application/check.py` adds the closed gap
  `declared_output_removed` (`DECLARED_OUTPUT_REMOVED_GAP`, defined in `kernel/task_facts.py`) to
  the check's task-fact gaps. It is agent-actionable, a `STOP_GATE_TOKENS` entry, and has a fixed
  `TASK_FACT_GAP_SENTENCES` sentence. `content_moved_declared_items(projection, states) ->
  tuple[(obligation, item index), ...]` names declared items whose state carries
  `base_lines`, `lines_lost` and `undeclared_lines_added` with `lines_lost >= 20`
  (`CONTENT_MOVED_MIN_LINES`), `2 * lines_lost >= base_lines` and
  `2 * undeclared_lines_added >= lines_lost`; the check then adds the standing disclosure
  `declared_output_content_moved` (`DECLARED_OUTPUT_CONTENT_MOVED_GAP`), never a Stop-gate token.
  `emptied_declared_items(projection, states, *, blocked=None, history=(), verified=False) ->
  tuple[(obligation, item index), ...]` (ADR-041, rewritten by ADR-045) is the `emptied` list of
  `assess_deliverables(projection, states, ...) -> DeliverableAssessment(states, emptied, removed)`:
  one verdict per **path**, from `deliverable_state_change(state, history, name=, other_growth=) ->
  DeliverableChange | None` (`emptied`, `truncated`, `removed`, `unchanged`; `None` unknown).
  `history` is `deliverable_history(records) -> tuple[DeliverableSnapshot(state, event_id,
  frontier)]` over the earlier `check_recorded` events' `deliverable_states`. A file is `emptied`
  only with proof of earlier content (`base_lines > 0`, or an earlier check read it with content);
  `truncated` needs 20 earlier lines and fewer than a tenth left (or 2,048 bytes and a tenth, when
  no line count was read), is not the content-moved shape, and is not a split (the other declared
  outputs gained at least half the lost lines, or their growth is unknown). `declared_output_emptied`
  (`DECLARED_OUTPUT_EMPTIED_GAP`, a Stop-gate token) fires when the change is emptied or truncated
  and an obligation declaring the path is resolved or claimed now, or an earlier check recorded the
  path with content with `basis` `delivered` or `verified`; the obligation's current status does
  not clear it. The exit is `path_assumption`: a `finishup-assumption:<obligation id>` decision of an
  obligation declaring the path whose statement or rationale names the declared value or the
  root-relative path as a whole token. `removed_declared_items(..., history=)` adds a file an
  earlier check recorded with content that is now gone.
  `RequestedOutputState.lines` is the current line count (tracked, untracked or unchanged).
  `deliverable_path_identity(relative) -> hmac-sha256:... | None` keys the history.
  `requested_output_states` fills `base_lines`, `lines_lost` and `undeclared_lines_added` for a
  declared `file` the change modifies (`M`) and `lines` for every existing declared `file`
  (ADR-045), through the optional adapter method `count_change_lines(workspace, base_commit,
  base_paths) -> ChangeLineCounts(changed: tuple[ChangeLineCount(path, added, removed,
  untracked), ...], base_lines, truncated)` (`ports/change_capture.py`): numstat for tracked
  changes, newline counts of untracked non-ignored files (bounded, no link followed, no
  credential-named or binary file), base line counts for the named paths; numbers only, nothing
  stored. A declared `directory` covers the files beneath it.
  `undeclared_reference_inputs(projection, states, blocked=) -> (deliverables, declared)` (tb4n2
  R2, #1022) returns the values of declared output `file` items that exist `inside` and were not
  deleted (obligations neither blocked nor `acknowledged_not_done`) and every `file`/`directory`
  value of any role. `application.check_change.undeclared_references(...) ->
  UndeclaredReferenceRead(pairs, ambiguous)` (tb4n4, #1044; it replaced
  `count_undeclared_references`; tb4n5 added the per-deliverable `ambiguous` counts) probes them,
  takes as candidates the files the check-time change created (untracked or `A`) that no declared
  value names or covers (pre-existing tracked files never count), and calls the optional adapter
  method `classify_undeclared_references(workspace, deliverables, candidates, declared=()) ->
  tuple[(deliverable index, candidate index, "dependency" | "ambiguous"), ...]` (at most 64 of
  each; `find_undeclared_references` is its dependency view; `declared` is every declared value of
  any role, root-relative): for at most 16 root-relative source deliverables (`.py .sh .bash .js
  .mjs .cjs .ts .rb .pl .r .R .jl .lua .php`, or no suffix with a `#!` first line) it reads at most
  256 KiB from the start, link-free, never a credential-named, multiply linked or binary file,
  resolves each one-line quoted literal (`'`, `"` or backtick) to the path the code builds from
  literals, and classifies the candidates it names (tb4n5, ADR-035 amendment): a composed path
  with a directory names by path only; a provable write (a supported API's destination argument,
  a literal write-only mode of that opener, never a container's append or read-write mode) is
  neither kind; any other naming may read the file; a bare basename that
  a declared file shares, or that nothing ties to the candidate's directory, is `ambiguous`. Only
  positions in the caller's own tuples leave the adapter. Any ambiguous count adds the standing
  disclosure `deliverable_references_ambiguous_name` (gap rule G4b; the receipt states the count,
  never a name). Any pair adds the agent-actionable
  task fact and Stop-gate token `deliverable_references_undeclared_file`
  (`DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP`; gap rule G0c, actionable on both routes, never a
  finding); any failure is `()`. The check records the referenced files on the referencing
  deliverable's `DeliverableState` (`undeclared_references`, below), so the receipt and the Stop
  gate name them; `delivered_set.undeclared_reference_rows(states)` and
  `task_fact_tokens.undeclared_reference_variants(rows)` are the one reading and the one sentence
  ("Undeclared files: <obligation> item <n> names \"<path>\" and ..."), each path through
  `bounded_text.quoted_path` (ASCII, one line, no double quote, at most 120 characters; the
  post-compaction recap uses the same helper). Only a `full_local` receipt names a path: under
  `default_local_export` and `redacted_share` the gap detail is cleared and the limitations section
  passes the rows without paths, so the sentence counts them ("... names 2 file(s)."). A disclosure
  decision never clears it; embedding the content, rebuilding it at run time, or declaring the file
  as a requested item does.
- **Work-integrity 0.3.0.** `requested_item_never_attempted` waits for `acting_started`, adds the
  absent-output fact, and skips blocked obligations. Since ADR-042 an item is reported only once a
  completion claim names its obligation or a published producing action names that obligation (or
  none), never for a `role: input` item; a published research or review action is not acting.
- **Task-fact scope (`kernel/task_fact_scope.py`, ADR-042).**
  `finding_obligation_scope(state, finding_id) -> frozenset[ObligationId]`,
  `task_fact_bears_on_finding(code, *, state, finding_id, markers) -> bool` and
  `scoped_resolution_reasons(reasons, *, state, finding_id, records) -> tuple[str, ...]` (drops the
  `coverage:<task fact>` reasons that do not bear on the finding, and since tb4n5 (#1049) a
  `coverage:command_attempt_mismatch` that no mismatched item bears on; never empties the list).
  `command_mismatches(state, records) -> tuple[CommandMismatch, ...]` lists the effective
  obligations' `asserted_observed_mismatch` items (`CommandMismatch(obligation_id, item_index,
  asserted_action_ids, observed_event_ids)`; memoized for the last projection, prefix and
  `task_facts.command_identity_key_generation()`), `command_mismatches_for_finding` the ones about
  one finding (all of them when a subject is missing, redacted or cannot be placed; a result or
  event subject resolves through its recorded action, so the linked observed run's result event
  relates) and `command_mismatch_bears_on_finding` whether any is (true when none is located). An
  obligation-scoped task fact also bears when a claim or obligation subject is missing or
  redacted, or an event subject no projection row records (or records unreadably). `self_verification_refusal` applies it; the
  `finding_not_proof_limited` refusal names those rows by id and index; readiness, the Stop gate and
  resolution stay task-wide.
- **Fact lineage and canonical commands (ADR-045, issue #1028).**
  `kernel/fact_lineage.FactLineage(code, rule, state, obligation_id, item_index, check_event_id,
  frontier, prior_event_id, prior_frontier, prior_size_bytes, prior_lines, now_size_bytes,
  now_lines, proof, basis, source_event_ids, accepted_by)` is the typed provenance of a derived
  fact (closed `rule`: `deliverable_path_history|deliverable_read|planned_command_match|
  planned_command_unmatched|edit_after_verification_run`; closed `state`; counts and ids only);
  `lineage_text(item)` is the one `Why:` renderer, `lineage_to_wire` / `lineage_from_wire` the wire
  mapping. `FactLineageModel` (`protocol/models.py`) is the wire object, carried as the optional
  `fact_lineage` list (at most 64) on `status` `closure_readiness` and on the check result, derived
  per request by `closure_readiness.current_fact_lineage(state, records, applicability)` from the
  applicable check's recorded `deliverable_states` plus `task_fact_signals(...).lineage`.
  `TaskFactSignals.lineage` covers `planned_verification_not_observed|failed|stale|
  matched_by_prefix` and `edited_after_last_verification`. `check_recorded` 1.4.0 gains the optional
  `deliverable_states` (at most 64 `DeliverableState`: `obligation_id`, `item_index`, `path_key`,
  `size_bytes`, `lines`, `base_lines`, `basis delivered|verified|present`, `change
  emptied|truncated|removed|unchanged`, `proof task_base|earlier_check`, `prior_size_bytes`,
  `prior_lines`, `prior_event_id`, `prior_frontier`, `accepted_by`, `unreviewable`, and since
  #1044 `undeclared_references` (at most 8 sorted root-relative paths of files the change created
  that this source deliverable names and no item declares: 1-256 characters, valid UTF-8, no control
  character, no leading `/`, no empty, `.` or `..` segment; the only path text the check records)
  with `undeclared_reference_count` when more were found than are named, and since tb4n5
  `undeclared_reference_ambiguous`, how many created files it names only ambiguously, never
  which; `undeclared_references_created_in_task` (`const true`) is read-compatibility only for
  payloads intermediate tb4n5 builds wrote before that provenance was withdrawn: it decodes and
  re-encodes byte-identically, no build produces it, and nothing consults it); absent when the
  check read no declared output file. Status
  `closure_readiness.undeclared_references` (optional on the unreleased status-result 1.4.0, at
  most 16 rows `{obligation_id, item_index, paths, total}`,
  `closure_readiness.current_undeclared_references` over the applicable check) carries them; each
  path is a `repository_excerpt` content leaf of every status view (a privacy policy can withhold
  it as the omission marker; a name the requesting writer itself published in this session
  returns to it under `self_authored`, above), and the MCP text summary never prints one. `domain/command_segments`: `canonical_words(argv)` (wrappers,
  assignments, basename, `python3`/`pythonX.Y` to `python`, `python -m pytest` to `pytest`),
  `canonical_command_commitments(key, argv) -> (full, prefixes, flags)`,
  `canonical_commitment(key, kind, payload)` (`full|prefix|flag`, domain-separated from segment
  commitments), `command_structure(normalized) -> CommandStructure(commands, composition,
  compound)`, `planned_segments(key, normalized)`, `strip_wrappers(argv)` and the single-layer
  `strip_one_wrapper(argv)` step. Each simple command also retains its original `sources` and
  whether it is `nested`, solely for executable-resolution checks; these are never recorded or
  added to canonical verification commitments.
  `command_segment_commitments` now also carries up to `MAX_CANONICAL_COMMITMENTS` (48) canonical
  commitments, `MAX_COMMAND_COMMITMENTS` (80) in all (the observed action `command` field, the hook
  structural list, the control-request 2.9.0 `maxItems` and `observed_failures` share that bound;
  the wire bound and the `write_scope` enum are generated from the hook's constants, #1039).
  `task_facts.requested_planned_command(value) -> PlannedCommand | None` and `planned_match(run,
  planned) -> PlannedMatch(outcome, kind) | None` with `kind` `exact|normalized|prefix|flags`;
  `prefix` and `flags` raise the standing `planned_verification_matched_by_prefix`.
  `task_facts.observed_planned_commands(projection, observed, cooperative, values)` is the set of
  requested command values some observed run matched; `command_attempts.same_requested_path` /
  `value_in_attempted` match a file in another spelling. `domain/shell_writes.shell_write_paths(
  command)` (literal, attributable paths only; linear; analyses at most `MAX_SHELL_WRITE_CHARS` =
  16,384 characters, up to the last newline, and drops the command a cut interrupts) and `shell_write_scope(command, *, workspace,
  inside, owned_roots=, relative_only=)` (outside wins, then `workspace`, then a single non-counting
  class; two non-counting classes count as `workspace`; a directory destination is classified by
  where it is, not by a notes or receipt file name; the hook calls it alone, with no separate
  outside-workspace check);
  `write_scope` admits `notes` (non-counting) and `workspace` (a shell command that writes the
  workspace; counts as an edit with `outside_workspace`; `observed_failures.SHELL_EDIT_TOKENS`).
  `missing_for_assessment.check_change_text_paths(capture)` lists the files the check-time change
  shows as text; `_TargetFiles.unsupported` decides by Git's NUL sniff first, then the suffix. The
  standing `declared_output_not_reviewable` (`DECLARED_OUTPUT_NOT_REVIEWABLE_GAP`) is raised when a
  review ran and a declared output file is a type the packet never carries.
  `GAP_CLASSIFICATION_VERSION` was `"7"` for this change (`"8"` since #1044).
- **Runner class.** `domain/observation_selection.command_runner_class` classifies
  `python -m <module>` by module (pytest/unittest/nose2/tox/nox/doctest `test`, mypy/pyright
  `typecheck`, ruff/flake8/pylint/pyflakes/pycodestyle `lint`, build/compileall `build`) and never
  counts an interpreter-run script as `build` by its name (ADR-042).
  `native_command_runner_class(argv)` unwraps at most one ordinary native host-shell layer for
  runner classification; nested executable spelling remains visible. Generic `finalize` and
  `*_regression` names grant no verification credit. Exploration additionally requires established
  executable resolution and closed non-writing arguments, independent of canonical verification
  matching. Since PR #1080 round 5 the exploration class of a shell command keeps failed exploratory
  reads out of failure accounting and advice only; it exempts nothing from closing-review or check
  currency, which follow the `workspace_effect` fact below. `RecordedPolicyVersionWire`,
  `CurrentPolicyPackWire`, `RecordedPolicyPackWire` and `RecordedVersionSlicePackWire` admit
  `work-integrity/0.3.0`; `POLICY_PACK_GENERATIONS` gains the `research-evidence/0.2.0` +
  `work-integrity/0.2.0` generation.
- **Runtime structural fields.** The observation envelope and control-request 2.9.0
  `structural_payload` admit `install_target` (`yoetz_runtime|workspace_env|private_env|system|
  unresolved`), `write_scope` (`outside_workspace|scratch|yoetz_owned|notes|workspace`; ADR-042:
  `scratch` and `yoetz_owned` name an edit whose every path is a temp root outside the workspace or
  FinishUP's own material; ADR-045: `notes` the agent's own notes, `workspace` a shell command that
  writes the workspace),
  `effective_user` (`root|non_root`) and `workspace_effect` (`unchanged|changed|unavailable`,
  PR #1080 round 5: produced only by `cli/workspace_effect_hook.workspace_fingerprint_pass` on a
  live `PostToolUse`, never copied from a host payload; materialization appends it to the observed
  result summary through `domain/workspace_effect.result_summary_with_workspace_effect`), the first
  three produced only by `cli/runtime_facts.runtime_structural_facts`, which judges `install_target`
  against the task interpreter (the agent's `python3`/`python` on the hook's `PATH`; ADR-033
  item 7). `observed_action_description(...,
  install_target=, write_outside_workspace=, effective_user=, write_scope=)` appends
  ` (install <class>)`, ` (write outside_workspace|scratch|yoetz_owned)`, ` (user <root|non_root>)`
  after the tool and runner suffixes; `observed_action_runtime_tokens(description)` reads them
  back and `observed_edit_counts(description)` is `False` only for a `scratch`/`yoetz_owned` edit,
  which never advances the latest edit or counts as acting (ADR-042). The Codex session stream
  names a `FileChange` item's `write_scope` from its own paths (never `outside_workspace`). A FinishUP
  MCP tool (`mcp__finishup__*`, `mcp__plugin_finishup_*__*`) always materializes as action kind `other`.
  `domain/write_scope.py`: `classify_write_path(path, *, workspace, inside, owned_roots) ->
  workspace|outside_workspace|scratch|yoetz_owned`, `edit_write_scope(classes) -> str | None`,
  `scratch_overlap(path)`, `finishup_artifact_name(path)`;
  `kernel.task_facts.non_counting_edits_exempt(projection) -> frozenset[str]` names the exempt write
  tokens per class (deliverables win: no `write scratch` exemption when a requested non-input item
  is under or contains a fixed temp root; no `write yoetz_owned` exemption when one has a receipt
  name or a requested non-input directory exists). Observation advice 0.1.8 adds the
  advice-only rule codes `install_into_yoetz_runtime`, `install_into_private_env`,
  `write_outside_workspace`.
- **Workspace fingerprint (PR #1080 rounds 5-6).** `adapters/workspace_fingerprint.WorkspaceFingerprintStore(directory, key_material, *, lingering=lingering_process)`:
  `capture_before(root, call_identity, *, deadline, host_deadline=None, excluded) -> reason | None`
  and
  `effect_after(root, call_identity, *, deadline, call_complete, excluded) -> WorkspaceEffectReading(effect, reason)`,
  `discard()`; `workspace_fingerprint_dir(observation_root, workspace_commitment)` is
  `<observation>/workspace-fingerprints/<commitment digest>/` (`pending/` per open call,
  `latest.bin` for digest reuse; owner-only; keyed BLAKE2b path and content digests plus a keyed
  MAC, never a path or byte of content; revoking observation removes it). Record format
  `FUWF\x02`: the header adds the call window start (`process_lifetime.process_clock_ns`), the
  capture-completion time and the host deadline (monotonic ns, 0 when absent), all under the MAC;
  a version-1 record reads as `no_pre_snapshot`. The walk covers every entry under the canonical
  workspace root without consulting ignore files. Inside `VCS_METADATA_DIRECTORIES` (`.git`,
  `.hg`, `.svn`) it skips the exact internal churn (`domain/workspace_effect.VCS_OPAQUE_DIRECTORIES`
  by identity: `objects`, `logs`, `refs`, `lfs`, `rr-cache`, `fsmonitor--daemon`, `modules`,
  `worktrees`, `lost-found`, `cursor`, `store`, `cache`, `wcache`, `pristine`, `tmp`;
  `vcs_bookkeeping_name`: `VCS_BOOKKEEPING_FILES`, `undo.*`, `*.lock`, and any `*index*` file
  directly in the metadata root) and compares the rest;
  `SHALLOW_DIRECTORY_NAMES` (`node_modules`, `.venv`, `venv`, `.tox`, `.nox`, `.pytest_cache`,
  `.mypy_cache`, `.ruff_cache`, `.hypothesis`) are compared at their first level (files by content,
  subdirectories by identity); `__pycache__` is walked without recording the directory itself or
  its bytecode (`domain/workspace_effect.bytecode_artifact_name`). It skips FinishUP receipt/export
  names (`saved_artifact_name`) and FinishUP state roots inside the workspace, never follows links,
  and is bounded by `MAX_ENTRIES` (60,000), depth 64 and `SNAPSHOT_SECONDS` (0.75) over the whole
  pass (cache load, cleanup, walk, hashing checked before every 256 KiB read, directory re-read,
  persistence), hashing at most `HASH_FILE_BYTES` (8 MiB) per file and `HASH_TOTAL_BYTES` (64 MiB)
  per snapshot. `capture_before` publishes nothing unless the capture finished before both the
  deadline and `host_deadline`. `effect_after` returns `unavailable`/`call_incomplete` when
  `lingering(window_ns, root)` is `True` (before the walk; `None` gives
  `process_table_unreadable`) or a walked directory's
  modification time moved during the walk, and `unavailable`/`timeout` when the record's capture
  missed its host deadline or the pass overran. Reasons:
  `no_pre_snapshot|call_incomplete|process_table_unreadable|too_large|timeout|unreadable|root_unusable|store_unusable`;
  `WorkspaceEffectReading(effect, reason, fresh)`. The degraded reasons (`too_large`, `timeout`,
  `unreadable`, `root_unusable`, `store_unusable`, `process_table_unreadable`: a standing
  condition marked once per ten minutes) are recorded once, when `fresh`, as hook
  diagnostics `workspace_fingerprint_<reason>`; a walk-bound back-off (`bounded` marker: ten
  minutes, two after a walk timeout; hashing, persistence and host-window overruns start none)
  skips walking meanwhile. `recently_bounded()`, `invalidate(call_identity, reason)`.
  `adapters/process_lifetime`: `process_clock_ns() -> int | None` (wall clock on macOS, boot clock
  on Linux, `None` elsewhere) and `lingering_process(window_ns, workspace_root) -> bool | None`
  (`True` when a same-user process started since `window_ns - PROCESS_CLOCK_SLACK_NS` (50 ms),
  still running, not a descendant of the hook's chain up to its host, has its working directory or
  a write-open file inside the root, or cannot be read; `None` when the process table cannot be
  read; never signals a process).
  `cli/workspace_effect_hook`: `fingerprinted_tool(tool_name, *, finishup_owned)` (shell/exec tools
  and every other tool except FinishUP's own, host-native reads, edits and a closed inert set),
  `host_call_complete(payload)` (an integer `exit_status`, a boolean `success` or `denied: true`,
  never with `run_in_background` or when `command_may_outlive_call(payload)` finds a background
  `&`, `nohup`, `setsid`, `disown` or similar in the command text: conservative only), `owned_relative_paths(workspace, roots)` and
  `workspace_fingerprint_pass(event, *, call_identity, workspace_locator, workspace_commitment,
  key_material, observation_root, complete, excluded, seconds, host_deadline)`, called by
  `handle_observe` before the observation store lock and only with an explicit locator (never on
  spool replay); `host_deadline` is the hook entry plus the host's hook window less
  `_FINGERPRINT_HOST_MARGIN_SECONDS`.
  `domain/workspace_effect`: `WORKSPACE_EFFECT_ANNOTATION_PREFIX` (`Observed workspace effect=`),
  `workspace_effect_annotation(effect)`, `workspace_effect_from_annotation(description)`,
  `path_beyond_workspace_fingerprint(value, *, directory=False, workspace_root=None)` (the walk's
  own rules below the root; out of scope outside `workspace_root` or for a relative path that
  leaves it; with no root, an absolute path is judged against each of its ancestors). `application/observation_materialize.materialize_workspace_effect_annotation(envelope, *, task_id, recorded_result_id, action_event_id, effect)`:
  one metadata-only observed `evidence_recorded` row (role `workspace_effect_<token>`, ids from
  the recorded result id and the token, causal parent the call's action event, no known gaps);
  `ObservationCoordinator._reconcile_workspace_effect` appends it after an ingest whose delivery
  carried a fact that the call's recorded result does not state.
  `kernel/later_material`: `WorkspaceEffects(quiet, changed, annotations)`, `workspace_effects(records,
  projection)` (folds result suffixes and annotations per action; `changed`/`unavailable` win; no
  action is quiet when `kernel/task_facts.declared_path_beyond_fingerprint(projection, *,
  workspace_root)` with `workspace_root=task_workspace_root(records)`, the one absolute
  `session_opened.workspace_ref` all of the task's sessions name, else `None`), rules
  `observed_workspace_unchanged` and `workspace_effect_of_action`; `classify_later_material(...,
  effects=)` and `closing_review_delta(record, projection, *, effects=None)` (no effects: no
  command is quiet; an annotation is judged as its call at its own position).
  `domain/observation_selection.without_routine_read(classification)` demotes a routine-read
  candidate to an individually recorded protected call.
- **Closure gate (`cli/closure_gate.py`).** `STOP_GATE_TOKENS` (in `kernel/task_facts.py`) are
  `obligations_open`, `receipt_findings_unresolved` (agent-work findings only),
  `finding_rejection_awaiting_ruling` (a finding the agent rejected with a reason that awaits the
  reviewer's ruling; the text sends the agent to `check` with `final_review: true` and never offers
  acknowledgement), `closing_review_required`, `planned_verification_failed`,
  `planned_verification_not_observed`, `planned_verification_stale`,
  `edited_after_last_verification` (ADR-042; observation-dependent like the planned-verification
  tokens), `requested_output_git_ignored`, `declared_output_removed`, `declared_output_emptied`
  (the last two are also voiced once per key on a Stop the host already continued, below), and
  `deliverable_references_undeclared_file` (#1044: the text tells the agent to embed the file,
  rebuild it at run time or declare it, or the directory holding it, as a delivered output, says
  disclosing the dependency does not clear it, and names the files from
  `closure_readiness.undeclared_references`: the one exception to closed tokens, counts and ids in
  the gate text; a path is never remembered. tb4n5: when a name was withheld it adds why and the
  agent's own listing command, `git status --porcelain --untracked-files=all`).
  `closure_gate_from_readiness(readiness, frontier_sequence=, frontier_digest=,
  observation_pending=, reasked_blockers=, active_stop=, final_message=, host=, code_mode=) ->
  ClosureGate(identity, text, items, blocker_keys) | None` asks the **re-checks
  `closure_readiness.rechecks` announces** (tb4n3 RC-8,
  ADR-033 amendment): `Recheck {kind: acceptance | acknowledgement | blocker | premise, key,
  subjects, rule, since_frontier}` with the keys `accept:<h8 of the sorted announced (flagged)
  resolved obligation ids>`,
  `ack:<obligation id>`, `blocker:<obligation id>:<kind>`, `premise:<acknowledged count>`. Status,
  `closure_prepare`, the CLI and the TUI show the same list; the gate never asks one status did
  not announce, and a readiness without the list (a service older than the gate) announces none.
  Items added: `BLOCKER_RECHECK_ITEM` (`blocker_recheck`), `ACKNOWLEDGEMENT_RECHECK_ITEM`,
  `PREMISE_RECHECK_ITEM`, `ACCEPTANCE_RECHECK_ITEM` (`acceptance_recheck`). Delivery memory stays
  client-side: `blocker_keys` holds the keys the gate asked (the historical field name): a blocker
  as `<obligation id>:<kind>`, `ack:<obligation id>`, `premise:<n>`,
  `accept:<h8>@<invite frontier>@m<closing_material_frontier>` when status names that field
  (otherwise `accept:<h8>@<invite frontier>`), and `emptied:<h8 of the declaring obligation items>`.
  The acceptance re-read matches the `@m` suffix: the same flagged set is not asked again while
  that material frontier is unchanged, including when the ledger frontier moves on bookkeeping,
  and is asked again when `closing_material_frontier` advances. A stored key without `@m` does not
  match a known material frontier, so the next Stop after the field appears asks once. Status
  that omits the field keeps the prefix match. The earliest invite frontier is the decimal before
  `@m`. An `acknowledgement` whose `since_frontier` is later than the earliest acceptance invite this session
  received answers that invite and is not asked (no invite-then-challenge). The acceptance sentence
  is never composed beside open obligations, a rejected finding awaiting a ruling, a withdrawn
  deliverable or an undeclared dependency (it then stays unasked). `finding_counts` (`to_do`, `awaiting_ruling`,
  `self_verify_eligible`) decides the finding count and whether `self_verified` is offered;
  `awaiting_ruling_findings` and `fact_lineage` give the ids and rules the text names, and
  `predicted_receipt` supplies the lowest-priority tail sentence (`predicted_receipt_variants`).
  When the gate fires and readiness `standing_limitations` lists `declared_output_content_moved`, the text
  carries one informational note; that code alone never fires the gate.
  `closure_gate_from_readiness(..., final_message=)` (tb4n5 #1050, ADR-033 amendment of
  2026-10-13; it replaced `acceptance_uncovered=`): the acceptance re-read names the obligations
  readiness announced (the ledger-flagged resolved set when the recheck's `rule` is
  `resolved_obligations_acceptance_risk`, with the flag sentence), except those the final message
  attests; `attested_acceptance(final_message, *, linked=False) -> frozenset[obligation id]` reads
  every exact `finishup-acceptance:<obligation id>:met` when `linked` is false (the legacy
  unflagged rule; any other outcome, `:not_met` included, is no attestation). When `linked` is
  true (rule `resolved_obligations_acceptance_risk`, #1079) only
  `finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` whose id is in
  `admissible` for that obligation, or `finishup-verification-limit:<obligation id>`, counts
  (legacy `yoetz-` spellings too). `admissible` is
  `closure_readiness.admissible_verification`; a missing argument or a missing row does not
  treat a well-formed id as linked. The list holds only an observed verification (hook-captured
  or observation-captured evidence, or a result of an observed command) linked to that
  obligation, its requested target, or a claim that lists that obligation. A claim with empty
  `obligation_refs` lends nothing. An agent-asserted id is unattested. A bare `:met` and
  prose that every criterion is met do not.
  The read is the first 65,536 characters. A cited id that is not admissible adds one sentence,
  `` `<id>` is not linked to obligation `<obligation id>`. ``, up to three, and copies no other
  message text. `unattested_acceptance(recheck, final_message, *, admissible=None, host=None) ->
  tuple[obligation id, ...] | None` passes `linked` from the recheck rule. It is `None` (every
  announced obligation is asked) without a message or when the announced subjects do not hash to
  the recheck's `accept:<h8>` key (more than eight, or an older list), else the announced
  obligations not attested; `()` means the re-read is not asked. On `cursor`, with no final
  message, a nonempty admissible set for an obligation is the record link that answers the
  flagged rule. The tb4n4 word-coverage rule (`uncovered_acceptance`) is removed. Where a legacy
  unflagged re-read rides alone it still ends with the sentence that a pure confirmation needs no
  new record, check or receipt. The flagged rule does not: saying every criterion is met does not
  answer it. The receipt evidence section states whether the ledger has the pairing
  (`claim_verification_lines`); the final-message line does not write that link.
  Both decision functions take `host=` and `code_mode=` (tb4n5 P6, #1079). `host` is the hook host
  the Stop came from. The required close instruction asks for the `check` with the cell's deadline
  pragma, `readiness_text.CODEX_CHECK_CELL_PRAGMA` (`// @exec: {"yield_time_ms": 300000}`, the
  bridge's `check` deadline), only when code mode was positively observed: `code_mode` is true
  (the hook saw a recorded `exec` cell for this session via
  `LocalObservationStore.session_observed_code_mode`) or `check_cause.tool` is `exec`. Otherwise
  the neutral sentence is used, including when `host` is `codex` (plain `exec_command` /
  `write_stdin` are not cells). There is no MCP `clientInfo` signal for this capability. Claude
  Code and Cursor do not record code-mode cells, so they keep the neutral sentence. On `cursor` the
  acceptance re-read never names the `finishup-acceptance` line (Cursor's `stop` carries no final
  message): it says a met criterion stays resolved and is confirmed in the final answer, and that
  the re-read is not asked again for the set until the work, its verification, or the review mode
  changes (#1050 follow-up, ADR-033); Codex and Claude Code keep the line.
  `readiness_text.check_cause_sentence` repeats the same pragma when the cause's `tool` is `exec`
  (the observed code-mode cell tool, not the host brand), in both its full and short forms.
  `read_closure_gate(..., final_message=, on_acceptance_covered=)` reads compact status (one read;
  the tb4n4 `obligations` page read is gone) and raises `ClosureGateUnavailable` when it cannot,
  and calls `on_acceptance_covered` when the message attests every announced obligation of an
  unasked acceptance re-read. The Codex Stop
  body's and the Claude Code Stop payload's `last_assistant_message` reach it in process only
  (`handle_observe(..., _stop_final_message=)` for Claude Code); Cursor's `stop` carries none.
  `closure_gate_already_delivered` / `record_closure_gate_delivered(..., blocker_keys=)` keep the
  owner-only `observation/closure-gate.json` once-per-frontier memory, and
  `closure_gate_reasked_blockers(session_id)` reads the per-session asked keys in
  `observation/closure-gate-blockers.json` (at most 64 per session). Both decision functions take
  `active_stop=` (#985): on a Stop the host already continued, only an announced re-check not yet
  asked (never `premise`) or a withdrawn deliverable (`declared_output_emptied` /
  `declared_output_removed`) whose `emptied:<h8>` key was not yet asked can continue the agent.
  `closure_gate_turn_blocks(session_id)` / `reset_closure_gate_turn` keep
  the per-turn count in `observation/closure-gate-turns.json`, capped at
  `MAX_GATE_BLOCKS_PER_TURN` (2); `record_closure_gate_delivered(..., active_stop=)` counts.
  `BLOCKER_UNCONFIRMED_TOKEN` (`obligation_blocker_unconfirmed`) is a gate item. Hook diagnostic
  reasons: `closure_gate_continued`, `closure_gate_blocker_rechecked`,
  `closure_gate_acceptance_rechecked` (the extra Stop turn the acceptance re-read costs),
  `closure_gate_acceptance_covered` (the final message attested every announced obligation, so
  the re-read was not asked; #1050),
  `closure_gate_active_stop_rechecked`, `closure_gate_not_required`,
  `closure_gate_repeat_suppressed`, `closure_gate_turn_end_after_continue` (an already-continued
  Stop that emitted nothing: the normal end of a continued turn; this is the former
  `closure_gate_loop_guard`, renamed because it guards no loop), `closure_gate_budget_exhausted`,
  `closure_gate_unavailable`. A route-less `status`
  control call uses the route the same session's MCP bridge named on its last successful
  `status` or `check` (`service/session_routes.SessionRouteMemory`, owner-only
  `session-routes.json` in the service state directory, 256 sessions, last writer wins), else
  the policy route; a route-less `check` is unchanged (ADR-033 amendment 2026-10-07).
  `set_standing_advice_withheld` / `standing_advice_withheld` carry standing advice a Codex or
  Claude Code Stop withheld to the first later `PostToolUse`.
  Before the gate reads status, the Stop pass drains the task's hook rows toward the current
  frontier and records `stop_drain_complete` or `stop_drain_incomplete`; `observation_pending` is
  true only when rows that can change this task's facts remain (#994).
- **Text surfaces.** `domain/receipts.TASK_FACT_GAP_SENTENCES` holds one fixed sentence per task-fact
  code; `check_time_change_gap_sentence(code)` returns it, so receipt gap details and limitations,
  `render_human_check`/`render_human_status` and the MCP check summary show it. A publish rejection
  whose validation pointer is `/event_drafts/<n>/payload/outcome` adds the fixed
  `_RESULT_OUTCOME_HINT` (closed outcome set, no `blocked`, the blocker line) to the MCP error text.
- **Scope.** The requested-output read runs only in `check`; status candidate findings and semantic
  assessment matching call `work_integrity_findings(case)` without `absent_outputs`.

A follow-up provider manifest changes a composed `supplied` request with no carried supplying
refs to `unavailable` when all of its composed supply refs are privacy-withheld. Packet-room
admission cuts remain `pending`. The dispatched `follow_up_round` is retained in either case,
and no withheld content is credited as supplied. This shared manifest reaches CLI, MCP, TUI
and all receipt renderings without a host-specific projection.

### Receipt prose and the agent-context ceiling (N5 privacy, 2026-10-14)

Receipt prose is FinishUP-authored and keeps its ordinary category policy in an `agent_context`
projection: section titles, sentences, codes, counts, IDs and coverage remain readable. The one
thing it can carry that the excerpt ceiling covers is a repository file name the check found and no
participant published (an undeclared-reference name, ADR-035), which a `full_local` receipt spells.
Each such name span is offered as its own `repository_excerpt` candidate. Unless the policy grants
repository excerpts, or the requesting writer published that exact name in this session through an
accepted, unredacted cooperative publication, the whole path token becomes
`(receipt prose withheld: repository_excerpt)`; the rest of the sentence stays. A span is the quoted
path the receipt prints, the bare path when it has a directory, or a basename with an extension. Any
name, a top-level one without an extension included, is also a span behind a leading `./` (also
`.//` or `././`), quoted or not, and empty or `.` segments inside the name still spell the same
file. Behind an absolute prefix (`/`, `~`, `~user`, `$VAR` or `${VAR}`, optionally behind `file://`)
any directories may come before the name's last component: an absolute path that ends in a withheld
file's base name counts as that file, which can only withhold more. Unquoted, the prefix's
directories stop at whitespace, at quotes and backticks, at `<` `>` `|` `,` `;` and brackets, and at
a `:` that starts another path (`:/`, `:~`, `:$`, `:./` or `:../`), so the next path in a list
starts afresh; a `:` inside a directory or a port (`host:8080/`) is kept. The whole prefixed token
is withheld. A path in single quotes, double quotes or backticks may run through directories with
spaces or the other quote characters (`"/r/Bob's/a.npz"`), and the whole quoted token is withheld
when the name ends the quoted text; a name earlier in the quotes (`"/r/x/b.npz /r/y/a.npz"`) is
found too, and its own path is withheld. An absolute path through a directory with spaces is not
recognised as one path when it is unquoted, since prose gives it no token boundary, or when anything
follows the name inside the quotes (`"/My Docs/a.npz:12"`); nor is an unquoted one through a
directory holding a stop character (`/r/Bob's/a.npz`), or a quoted one through a directory holding
its own closing quote. A name glued to other characters and then a `/` (`/r/a.npz~/x`), or followed
by a `:` and a bare relative path (`/r/a.npz:rel/x`, or grep's `/r/a.npz:12:rel/x`), reads as a
directory of a longer path and stays readable: the prefix never gives a directory back, which keeps
each search linear. A different relative directory (`../`, `x/`), a longer name, a suffix, a plain
word such as `Summary` (or a top-level name written without a prefix or quotes), and a different
letter case stay readable: spellings are compared exactly, because folding case or Unicode would
conflate distinct files on a case-sensitive filesystem. Every bound in the span pattern is fixed, so
a search stays linear in the prose it reads. The rule applies to JSON, markdown and text and to
every profile, `full_local` included: a format or profile is not a disclosure grant.

The token can be longer than the name it replaces. A field that would then pass its wire bound
(32,768 characters for `human_text`, at least its original length for a document field) or the
16 KiB per-item privacy bound is cut deterministically at a whole token and ends with a visible
`[receipt text truncated after withholding: N characters not shown]` marker; only text already
past the withholding is dropped, and the audit still records every per-name decision.
`privacy_projection.omitted_pointers` names each affected result field. Past the 512-pointer wire
bound the list coalesces deterministically to containing fields, so a large receipt still renders;
the local disclosure audit keeps one decision per name and field
(`<field pointer>/@repository_name/<name index>`). The digest and object ID identify the unchanged
stored owner receipt. An earlier stored receipt meets the same rule when reread, with name
provenance read at the current ledger head, so redacting the publication that spelled a name
withdraws it. A denied ordinary prose category keeps its existing omission behavior; JSON still
fails closed when that denial would need an object marker inside the receipt document.

Every client result is agent-facing (`agent_context`): the CLI, the terminal interface, MCP tools
and hooks alike. A terminal, a human-readable rendering, a client kind or the user ID is a
presentation fact an agent can reproduce (a pseudo-terminal passes every terminal test), so none of
them selects the owner's view, and the service ignores them as authority. The owner's full receipt
(`local_human_view`) needs an explicit request, `finishup receipt --owner-view` or *Your full receipt*
in the terminal interface, and a human-control `owner_receipt_view` ceremony: the owner
reauthenticates with operating-system presence or the vault passphrase for that exact receipt
request. The grant belongs to the command's own control connection as the service admitted it: the
service mints an opaque identity for every admitted connection and never takes one from the client,
refuses any connection whose hello nonce is already live or was used before, mints the grant only
for the one live connection the ceremony target names, consumes it only on a receipt call on that
connection, and revokes it when the connection closes. The grant is one-use and expires after 60
seconds. There is no standing grant, and the agent-attested consent lane cannot stand in for it.
Anyone holding the terminal can type into the prompt, a pseudo-terminal included; the boundary is a
passphrase or presence check the agent cannot pass. On macOS the packaged service composes one
operating-system presence provider, Apple LocalAuthentication: the service itself raises a system
dialog (Touch ID or the device password) whose text is fixed apart from a confirmation code the
owner's own command also prints, and only its exact approval for that exact challenge becomes a
one-use attestation the vault consumes. A client can name that source but can assert nothing. The
provider serves only this ceremony, on either vault mode. A passphrase stays offered beside it: when
the service cannot show a dialog, the command asks for the passphrase once instead, but it never
asks for a passphrase kept in the platform credential store (setup's system-keychain choice
generates one its owner never saw) unless the owner passes `--use-passphrase`, which also skips the
dialog, for example over SSH. A cancelled or failed dialog is `presence_refused` and an unanswered
one is `presence_timeout` after 60 seconds; neither grants anything, and the next dialog then waits
(`reauthentication_rate_limited`, 5 seconds rising to 5 minutes). That wait lives in the service
process and a restart clears it, so it slows repeated dialogs rather than capping them, and an agent
that causes misses can delay the owner's own dialog by up to 5 minutes. Dialogs start at least 5
seconds apart even when each is cancelled at once. A throttled passphrase (30 seconds after the
third wrong one, doubling to 5 minutes, kept across a restart) is reported as such, without the
restart hint. Another open confirmation is `ceremony_busy` (`owner_view_busy`, naming this command's
code), never a locked vault; a silent one holds the slot until its five-minute binding expires or
the service restarts. Linux and WSL 2 compose no provider: there only a vault passphrase the owner
types completes the ceremony, and a vault without one, or with one kept in the credential store,
fails closed with `owner_view_unavailable`. A command with no foreground terminal to prompt on (for
example a headless session) fails with `owner_view_requires_terminal`. Either way it shows nothing
and points to the next step. Linux and WSL 2 use the same code but were not exercised for this
change, and no real Touch ID prompt was exercised by automation (ADR-009 round 5). An agent that
runs the command can make the dialog appear but cannot answer it, so approve it only when you asked
for the full receipt yourself. A process running as the owner's account that can already read the
vault passphrase (for example from an auto-unlock keyring entry) is outside this boundary, as for
every passphrase reauthentication (ADR-008).

The shared `Application.project_result_for_client` builds the name spans in
`application/receipt_projection.py`: names come from every check recorded through the receipt's
subject frontier, and authorship from `published_name_authorship` keyed once per distinct name at
`/receipt_repository_names/<index>` (at most 128). The ordinary-category candidate for a field
carries its prose with every name span already withheld and bounded, so a denied name never enters
the authorized sink payload under another category. `resolve_client_disclosure_sink` returns
`local_human_view` only for a `ClientProjectionContext(owner_view=True)` on a `cli` or `ui` call;
only the daemon sets that flag, after `service/owner_view.py` consumed a grant whose target digest
binds the receipt request's task, session, request ID, format, include and profile to a digest of
the control connection nonce. `OwnerViewGrants.admit` gives every admitted control connection a
service-minted admission identity and refuses a nonce that is live or was already admitted;
`issue` resolves the target's connection digest to that one live admission (no live connection,
no grant: the ceremony fails `target_invalid`); `consume(admission, target)` succeeds once, on
that admission only; `release` on disconnect revokes its grants. Other result methods keep their classifications. Codex, Claude Code
and Cursor share this service boundary; MCP summaries and the Stop gate use projected fields and
structural counts.

Native verification-output follow-ups (issue #1079, F1): keyed `omitted:` command
actions use service-authenticated post-tool command input bound to the output's exact
capture phase and keyed action identity. Hooks retain this context locally under the
existing capture consent and byte budget; the input is never sent to the reviewer.
The same verification classification, environment/path refusal and whole-item secret
gates apply. Absent, partial, redacted or differently bound context withholds the output.
Private and repository-excerpt denial still send no auto-supplied output.
Plaintext actions cannot authorize auto-supply. The ledger contains keyed command
identities, closed outcome metadata, object/evidence references, digests and byte/part
counts; post-tool command input remains encrypted local capture material and is never
included in the provider excerpt.

Unanswered acceptance invitations (issue #1079, F2) do not establish coverage.
Delivery memory bounds Stop prompting only. Risky resolved obligations without an
admissible observed verification link or recorded verification-limit decision retain
the derived `unresolved_verification_limitation` check/readiness gap. The receipt and
MCP summary explicitly name the affected obligations and the unresolved verification
limitation. The receipt remains coverage-bounded after Stop is allowed.
