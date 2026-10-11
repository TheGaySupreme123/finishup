# Architecture decision records

ADRs are the top authority for public behavior. When an ADR and a page under `docs/` disagree, the
ADR wins; when an ADR and the code disagree, that is a bug in one of them and worth an issue.

| ADR | Decision |
|---|---|
| [001](ADR-001-writer-topology.md) | Writer topology |
| [002](ADR-002-canonical-protocol.md) | Canonical protocol |
| [003](ADR-003-storage-sqlite-durability.md) | Storage: SQLite durability |
| [004](ADR-004-threat-crypto-key-recovery.md) | Threat model, crypto, key recovery |
| [005](ADR-005-codex-capability-identity.md) | Codex capability identity |
| [006](ADR-006-semantic-provider-profile.md) | AI-powered review provider profiles |
| [007](ADR-007-packaging-platform-release.md) | Packaging, platform, release |
| [008](ADR-008-local-service-vault-trust-boundary.md) | Local service and vault trust boundary |
| [009](ADR-009-data-egress-privacy.md) | Data egress and privacy |
| [010](ADR-010-harness-integration-port.md) | Harness integration port |
| [011](ADR-011-structural-subject-state-capture.md) | Structural subject-state capture |
| [012](ADR-012-first-run-setup-wizard.md) | First-run setup wizard |
| [013](ADR-013-interactive-control-menu.md) | Interactive control menu |
| [014](ADR-014-toml-settings-and-owner-declared-endpoint.md) | TOML settings and owner-declared endpoint |
| [015](ADR-015-elevated-bootstrap-consent.md) | Elevated bootstrap consent |
| [016](ADR-016-human-review-non-default-actions.md) | Human review for non-default actions |
| [017](ADR-017-full-screen-terminal-interface.md) | Full-screen terminal interface |
| [018](ADR-018-host-declared-mcp-route-egress-ceiling.md) | Host-declared MCP route egress ceiling |
| [019](ADR-019-declared-completion-scope.md) | Declared completion scope |
| [020](ADR-020-typed-evidence-digest-provenance.md) | Typed evidence digest provenance |
| [021](ADR-021-recommended-defaults-advisories-and-update-check-surfacing.md) | Recommended-defaults advisories and update-check surfacing |
| [022](ADR-022-harness-observation-writer-identity-and-observation-tolerant-concurrency.md) | Harness observation writer identity and observation-tolerant concurrency |
| [023](ADR-023-portable-plugin-carrier-host-activation.md) | Portable plugin carrier and host activation |
| [024](ADR-024-installation-vault-recovery.md) | Installation-vault recovery |
| [025](ADR-025-versioned-claim-correction.md) | Versioned append-only claim correction |
| [026](ADR-026-isolated-root-runtime-identity.md) | Exact-target isolated-root runtime identity |
| [027](ADR-027-task-lineage-and-project-scope.md) | Task lineage and project scope |
| [028](ADR-028-instance-identity-and-runtime-pinned-roots.md) | Instance identity and runtime-pinned isolated roots |
| [029](ADR-029-smart-observation-selection.md) | Smart observation selection and bounded observation budgets (proposed; amended for #828 capacity policy) |
| [030](ADR-030-typed-recovery-directives.md) | Typed recovery directives for public errors (proposed) |
| [031](ADR-031-check-time-change-capture.md) | The service captures the check-time change as one reviewed object |
| [032](ADR-032-closure-readiness-checklist-and-material-dependency-coverage.md) | Closure readiness as a checklist, and material-dependency coverage (proposed) |
| [034](ADR-034-proof-limited-findings-self-verified.md) | Proof-limited findings: the `self_verified` respond disposition |
| [040](ADR-040-reviewer-disagreement-and-route-derived-review.md) | Binding rules for reviewer disagreement (`disputed_after_rebuttal`); review requirement derived from the route |
| [041](ADR-041-obligation-status-re-derived-and-refusal-reasons.md) | Obligation status re-derived from current evidence, one obligation version rule, refusals that say why |
| [043](ADR-043-bounded-agent-facing-text.md) | Bounded agent-facing text: one never-failing composer, and a committed operation never fails on its text |
| [044](ADR-044-post-compaction-recap.md) | A bounded, sourced recap of Yoetz state when a host resumes after compaction |
| [045](ADR-045-derived-facts-history-and-lineage.md) | Derived facts carry history (path-keyed deliverable state) and lineage; canonical command commitments; attempts; binary by content first |

Unresolved gates are centralized in [`docs/OPEN_QUESTIONS.md`](../OPEN_QUESTIONS.md), not scattered
through individual ADRs.

## A note on the retired spec tree

Yoetz was built spec-first: every planned file had one Markdown owner at a mirrored path under
`specs/`. That tree completed its purpose — all 626 declared files were built — and was retired on
2026-07-25 rather than maintained as a second copy of a shipped system.

Each ADR's **Implemented by** line now names real modules, suites, and resources. Some ADR bodies
still contain prose written while the tree existed; where such text refers to an "owning spec", read
it as the code and tests for that path. The final state of the tree is recoverable in full:

```text
git show specs-tree-final:specs/FILE_MANIFEST.md
git show specs-tree-final:specs/<path>
```
