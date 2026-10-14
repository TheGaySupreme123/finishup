"""Versioned agent-safe consent catalog, pending, status, and result contracts."""

from __future__ import annotations

from typing import Annotated, Final, Literal, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic_core.core_schema import SerializerFunctionWrapHandler

from finishup.domain.privacy import PrivacyPolicyChange, PrivacyPolicyChangeValue, ProviderBinding
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import (
    CanonicalPositiveUInt64Wire,
    EventIdWire,
    ProjectIdWire,
)

__all__ = [
    "CONSENT_PENDING_TTL_SECONDS",
    "AgentSafePendingModel",
    "ConsentCatalogModel",
    "ConsentCatalogOperationModel",
    "ConsentPrepareResultModel",
    "ConsentProjectCoordinationGrantResultModel",
    "ConsentReviewResultModel",
    "ConsentStatusModel",
    "CoordinationBindingModel",
    "ImportPublicationPreviewModel",
    "PrivacyPolicyChangeModel",
    "RepositoryPrivacyGrantPreviewModel",
    "RepositoryPrivacyProviderBindingModel",
    "RepositoryPrivacyRecipe",
    "ProjectCoordinationGrantBindingModel",
]

# The one prepared-pending lifetime (docs/INTERFACES.md): every prepared consent action expires
# exactly this many seconds after prepare. Shared here so agent-facing surfaces can state the
# bound without importing the trusted pending store.
CONSENT_PENDING_TTL_SECONDS: Final = 15 * 60
REPOSITORY_PRIVACY_PREVIEW_MAX_BYTES: Final = 32_768

type ConsentOperation = Literal[
    "vault_initialize",
    "vault_passphrase_rotate",
    "provider_credential_set",
    "provider_credential_rotate",
    "repository_privacy_grant",
    "project_coordination_grant",
    "import_publication",
    "idle_relock_disable",
    "privacy_policy_widen",
    "backup_execute",
    "restore_execute",
    "migrate_execute",
    "skill_install",
    "plugin_artifact_apply",
    "harness_mcp_register",
]
type RiskClass = Literal[
    "default_safe",
    "secret_ingress",
    "secret_reauth",
    "review_only",
    "privacy_widen",
]
type Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
type Commitment = Annotated[str, Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")]
type PendingId = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
type BoundedText = Annotated[str, Field(min_length=1, max_length=2048)]
type RepositoryPrivacyRecipe = Literal[
    "assisted_review", "expanded_review", "private", "metadata_only"
]

_CLOSED_CONFIG = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class _ClosedModel(BaseModel):
    model_config = _CLOSED_CONFIG


class ImportPublicationPreviewModel(_ClosedModel):
    schema_: Literal["yoetz.import-publication-preview/1"] = Field(alias="schema")
    authorization_target_digest: Digest
    source_identity_digest: Digest
    capture_manifest_commitment: Commitment
    publication_plan_digest: Digest
    task_id: Annotated[
        str,
        Field(pattern=r"^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    ]
    session_id: Annotated[
        str,
        Field(pattern=r"^ses_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    ]
    writer_id: Annotated[
        str,
        Field(pattern=r"^wri_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    ]
    codex_capability_profile_id: Annotated[str, Field(min_length=1, max_length=128)]
    codex_capability_profile_digest: Digest
    codex_version: Annotated[str, Field(min_length=5, max_length=128)]
    mapping_version: Annotated[str, Field(min_length=1, max_length=128)]
    source_byte_count: Annotated[int, Field(ge=0, le=4_194_304)]
    source_line_count: Annotated[int, Field(ge=0, le=20_000)]
    candidate_count_upper_bound: Annotated[int, Field(ge=0, le=102_400)]
    gap_count_upper_bound: Annotated[int, Field(ge=0, le=20_000)]
    batch_count: Annotated[int, Field(ge=0, le=1_024)]
    publication_count: Annotated[int, Field(ge=1, le=1_025)]
    max_source_bytes: Literal[4_194_304]
    max_line_bytes: Literal[1_048_576]
    max_lines: Literal[20_000]
    max_excerpt_bytes: Literal[8_192]
    max_events_per_batch: Literal[100]
    max_batches: Literal[1_024]
    complete_transcript_included: Literal[False]
    reasoning_items_included: Literal[False]
    reviewer_egress_changed: Literal[False]


class PrivacyPolicyChangeValueModel(_ClosedModel):
    kind: Literal["none", "flag", "count", "labels"]
    flag: bool | None
    count: Annotated[int, Field(ge=0)] | None
    labels: tuple[Annotated[str, Field(min_length=1, max_length=192)], ...] = Field(max_length=64)

    @field_validator("labels", mode="before")
    @classmethod
    def _adapt_labels(cls, value: object) -> object:
        return tuple(cast(list[object], value)) if type(value) is list else value

    @model_validator(mode="after")
    def _validate_closed_value(self) -> Self:
        PrivacyPolicyChangeValue(
            kind=self.kind,
            flag=self.flag,
            count=self.count,
            labels=self.labels,
        )
        return self

    @classmethod
    def from_domain(cls, value: PrivacyPolicyChangeValue) -> Self:
        return cls(kind=value.kind, flag=value.flag, count=value.count, labels=value.labels)

    def to_domain(self) -> PrivacyPolicyChangeValue:
        return PrivacyPolicyChangeValue(
            kind=self.kind,
            flag=self.flag,
            count=self.count,
            labels=self.labels,
        )


class PrivacyPolicyChangeModel(_ClosedModel):
    area: Literal["global", "review", "channel", "local_model", "agent_context", "human_control"]
    field: Annotated[str, Field(min_length=1, max_length=64)]
    subject: Annotated[str, Field(min_length=1, max_length=192)] | None
    before: PrivacyPolicyChangeValueModel
    after: PrivacyPolicyChangeValueModel
    widens: bool

    @model_validator(mode="after")
    def _validate_closed_change(self) -> Self:
        self.to_domain()
        return self

    @classmethod
    def from_domain(cls, value: PrivacyPolicyChange) -> Self:
        return cls(
            area=value.area,
            field=value.field,
            subject=value.subject,
            before=PrivacyPolicyChangeValueModel.from_domain(value.before),
            after=PrivacyPolicyChangeValueModel.from_domain(value.after),
            widens=value.widens,
        )

    def to_domain(self) -> PrivacyPolicyChange:
        return PrivacyPolicyChange(
            area=self.area,
            field=self.field,
            subject=self.subject,
            before=self.before.to_domain(),
            after=self.after.to_domain(),
            widens=self.widens,
        )


class RepositoryPrivacyProviderBindingModel(_ClosedModel):
    provider_id: Annotated[str, Field(min_length=1, max_length=128)]
    model_id: Annotated[str, Field(min_length=1, max_length=128)]
    endpoint_profile_id: Annotated[str, Field(min_length=1, max_length=128)]
    endpoint_profile_version: Annotated[str, Field(min_length=1, max_length=128)]
    transport: Literal["external"]

    @model_validator(mode="after")
    def _validate_provider_binding(self) -> Self:
        self.to_domain()
        return self

    @classmethod
    def from_domain(cls, value: ProviderBinding) -> Self:
        return cls(
            provider_id=value.provider_id,
            model_id=value.model_id,
            endpoint_profile_id=value.endpoint_profile_id,
            endpoint_profile_version=value.endpoint_profile_version,
            transport="external",
        )

    def to_domain(self) -> ProviderBinding:
        return ProviderBinding(
            self.provider_id,
            self.model_id,
            self.endpoint_profile_id,
            self.endpoint_profile_version,
            self.transport,
        )


class RepositoryPrivacyGrantPreviewModel(_ClosedModel):
    """Agent-safe exact before/after view of one prepared repository grant."""

    schema_: Literal["yoetz.repository-privacy-grant-preview/1"] = Field(alias="schema")
    recipe: RepositoryPrivacyRecipe
    repository_privacy_commitment: Commitment
    authority_digest: Digest
    current_policy_digest: Digest
    candidate_policy_digest: Digest
    diff_digest: Digest
    candidate_profile: Literal[
        "local_only", "confirm_every_request", "minimal_external", "trusted_provider"
    ]
    candidate_review_context: Literal["structural", "assisted", "expanded"]
    candidate_provider_binding: RepositoryPrivacyProviderBindingModel | None
    changes: tuple[PrivacyPolicyChangeModel, ...] = Field(max_length=128)

    @field_validator("changes", mode="before")
    @classmethod
    def _adapt_changes(cls, value: object) -> object:
        return tuple(cast(list[object], value)) if type(value) is list else value

    @model_validator(mode="after")
    def _bind_diff_digest(self) -> Self:
        encoded: list[JsonValue] = [
            cast(JsonValue, change.model_dump(mode="json")) for change in self.changes
        ]
        if len(canonical_encode(encoded)) > REPOSITORY_PRIVACY_PREVIEW_MAX_BYTES:
            raise ValueError("repository_privacy_preview_too_large")
        if canonical_digest(encoded) != self.diff_digest:
            raise ValueError("repository_privacy_preview_diff_mismatch")
        return self


class CoordinationBindingModel(_ClosedModel):
    """Exact, generation-bound binding for local project coordination consent."""

    schema_: Literal["yoetz.project-coordination-grant-binding/1"] = Field(alias="schema")
    project_id: ProjectIdWire
    membership_generation: CanonicalPositiveUInt64Wire
    action: Literal["grant"]
    audit_record_id: EventIdWire

    @model_validator(mode="after")
    def _validate_generation_bound(self) -> Self:
        # The coordination authority stores this value as a JSON number only after parsing the
        # canonical string, so keep the public binding inside its exact IEEE-754 safe range.
        if int(self.membership_generation) > 2**53 - 1:
            raise ValueError("coordination_binding_generation_invalid")
        return self


# Keep the operation-shaped spelling available to adapters that use the full contract name.
ProjectCoordinationGrantBindingModel = CoordinationBindingModel


class AgentSafePendingModel(_ClosedModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"operation": {"const": "repository_privacy_grant"}},
                        "required": ["operation"],
                    },
                    "then": {
                        "properties": {
                            "repository_privacy_recipe": {"not": {"type": "null"}},
                            "repository_privacy_preview": {"not": {"type": "null"}},
                            "import_publication_preview": {"type": "null"},
                        }
                    },
                    "else": {
                        "properties": {
                            "repository_privacy_recipe": {"type": "null"},
                            "repository_privacy_preview": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"operation": {"const": "import_publication"}},
                        "required": ["operation"],
                    },
                    "then": {
                        "properties": {"import_publication_preview": {"not": {"type": "null"}}}
                    },
                    "else": {"properties": {"import_publication_preview": {"type": "null"}}},
                },
                {
                    "if": {
                        "properties": {"operation": {"const": "project_coordination_grant"}},
                        "required": ["operation"],
                    },
                    "then": {"properties": {"coordination_binding": {"not": {"type": "null"}}}},
                    "else": {"properties": {"coordination_binding": {"type": "null"}}},
                },
            ]
        },
    )

    schema_: Literal["yoetz.consent.pending-agent/6", "yoetz.consent.pending-agent/7"] = Field(
        alias="schema"
    )
    operation: ConsentOperation
    risk_class: RiskClass
    pending_id: PendingId
    danger_digest: Digest
    danger_text: BoundedText
    expires_at_unix: Annotated[int, Field(gt=0)]
    target_digest: Digest
    repository_privacy_recipe: RepositoryPrivacyRecipe | None
    repository_privacy_preview: RepositoryPrivacyGrantPreviewModel | None
    import_publication_preview: ImportPublicationPreviewModel | None
    coordination_binding: CoordinationBindingModel | None = None
    review_command: tuple[Literal["finishup"], Literal["consent"], Literal["review"]]
    authorize_command: tuple[Literal["finishup"], Literal["consent"], Literal["authorize"]] | None

    @field_validator("review_command", "authorize_command", mode="before")
    @classmethod
    def _adapt_commands(cls, value: object) -> object:
        return tuple(cast(list[object], value)) if type(value) is list else value

    @model_validator(mode="after")
    def _bind_operation_preview(self) -> Self:
        if self.operation == "repository_privacy_grant":
            if (
                self.repository_privacy_recipe is None
                or self.repository_privacy_preview is None
                or self.repository_privacy_recipe != self.repository_privacy_preview.recipe
                or self.import_publication_preview is not None
            ):
                raise ValueError("repository_privacy_preview_invalid")
        elif (
            self.repository_privacy_recipe is not None
            or self.repository_privacy_preview is not None
        ):
            raise ValueError("repository_privacy_preview_forbidden")
        if (self.operation == "import_publication") != (
            self.import_publication_preview is not None
        ):
            raise ValueError("import_publication_preview_invalid")
        if (self.operation == "project_coordination_grant") != (
            self.coordination_binding is not None
        ):
            raise ValueError("coordination_binding_invalid")
        return self

    @model_serializer(mode="wrap")
    def _serialize_versioned(self, serializer: SerializerFunctionWrapHandler) -> dict[str, object]:
        """Keep v6 projections byte-compatible while v7 carries the new nullable field."""

        result = cast(dict[str, object], serializer(self))
        if self.schema_ == "yoetz.consent.pending-agent/6":
            result.pop("coordination_binding", None)
        return result


class ConsentCatalogOperationModel(_ClosedModel):
    operation: ConsentOperation
    risk_class: RiskClass
    summary: BoundedText
    implemented: bool
    requires_provider_binding: bool
    requires_grant_binding: bool
    requires_target_digest_arg: bool
    agent_chat_authorize_allowed: bool
    prepare_hint: BoundedText


class ConsentRulesModel(_ClosedModel):
    forbidden_secret_channels: tuple[
        Literal["mcp"],
        Literal["argv"],
        Literal["env"],
        Literal["config"],
        Literal["transcript"],
    ]
    no_standing_yolo: Literal[True]
    path_safety_not_waivable_by_consent: Literal[True]
    independent_user_presence_required_for_agent_chat: Literal[False]
    trusted_console_is_not_authority: Literal[True]
    one_pending_at_a_time: Literal[True]
    approval_arguments_forbidden: Literal[True]
    agent_selected_initialization_secret_forbidden: Literal[True]
    authorized_one_shot_stdin_permitted: Literal[True]
    agent_attested_current_chat_instruction_permitted: Literal[True]
    agent_attestation_is_independent_proof: Literal[False]
    compromised_agent_can_forge_attestation: Literal[True]
    explicit_current_user_outcome_controls_supported_choice: Literal[True]
    recommendations_are_advisory: Literal[True]
    technical_authority_and_safety_boundaries_remain_enforced: Literal[True]

    @field_validator("forbidden_secret_channels", mode="before")
    @classmethod
    def _adapt_never_channels(cls, value: object) -> object:
        return tuple(cast(list[object], value)) if type(value) is list else value


class ConsentCatalogModel(_ClosedModel):
    schema_: Literal["yoetz.consent.catalog/6", "yoetz.consent.catalog/7"] = Field(alias="schema")
    default_safe: tuple[
        Literal["mcp.start"],
        Literal["mcp.publish_work"],
        Literal["mcp.check"],
        Literal["mcp.respond"],
        Literal["mcp.status"],
        Literal["mcp.receipt"],
        Literal["privacy.tighten"],
    ]
    rules: ConsentRulesModel
    operations: tuple[ConsentCatalogOperationModel, ...]

    @field_validator("default_safe", "operations", mode="before")
    @classmethod
    def _adapt_catalog_arrays(cls, value: object) -> object:
        return tuple(cast(list[object], value)) if type(value) is list else value


class ConsentStatusModel(_ClosedModel):
    schema_: Literal["yoetz.elevated-bootstrap.status/6", "yoetz.elevated-bootstrap.status/7"] = (
        Field(alias="schema")
    )
    pending: AgentSafePendingModel | None
    consent_catalog: ConsentCatalogModel


class ConsentPrepareResultModel(_ClosedModel):
    schema_: Literal[
        "yoetz.elevated-bootstrap.prepare-result/6",
        "yoetz.elevated-bootstrap.prepare-result/7",
    ] = Field(alias="schema")
    pending: AgentSafePendingModel


class ConsentDeniedResultModel(_ClosedModel):
    decision: Literal["denied"]


class ConsentVaultInitializedResultModel(_ClosedModel):
    state: Literal["ready"]
    reason: Literal["succeeded"]


class ConsentProviderCredentialResultModel(_ClosedModel):
    action: Literal["set", "rotate"]
    generation: Annotated[int, Field(gt=0)]
    outcome: Literal["active", "local_only", "stored"]


class ConsentRepositoryPrivacyGrantResultModel(_ClosedModel):
    recipe: RepositoryPrivacyRecipe
    outcome: Literal["granted", "tightened", "denied"]


class ConsentImportPublicationResultModel(_ClosedModel):
    authorization_target_digest: Digest
    outcome: Literal["authorized"]


class ConsentProjectCoordinationGrantResultModel(_ClosedModel):
    """Approved result for one exact project membership generation."""

    project_id: ProjectIdWire
    membership_generation: CanonicalPositiveUInt64Wire
    audit_record_id: EventIdWire
    outcome: Literal["granted"]

    @model_validator(mode="after")
    def _validate_generation_bound(self) -> Self:
        if int(self.membership_generation) > 2**53 - 1:
            raise ValueError("coordination_result_generation_invalid")
        return self


class ConsentReviewResultModel(_ClosedModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        json_schema_extra={
            "oneOf": [
                {
                    "properties": {
                        "operation": {
                            "enum": [
                                "vault_initialize",
                                "vault_passphrase_rotate",
                                "provider_credential_set",
                                "provider_credential_rotate",
                                "repository_privacy_grant",
                                "project_coordination_grant",
                                "import_publication",
                            ]
                        },
                        "risk_class": {
                            "enum": [
                                "privacy_widen",
                                "secret_ingress",
                                "secret_reauth",
                                "review_only",
                            ]
                        },
                        "outcome": {"const": "denied"},
                        "result": {
                            "type": "object",
                            "properties": {"decision": {"const": "denied"}},
                            "required": ["decision"],
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "vault_initialize"},
                        "risk_class": {"const": "secret_ingress"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "state": {"const": "ready"},
                                "reason": {"const": "succeeded"},
                            },
                            "required": ["state", "reason"],
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "vault_passphrase_rotate"},
                        "risk_class": {"const": "secret_reauth"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "state": {"const": "ready"},
                                "reason": {"const": "succeeded"},
                            },
                            "required": ["state", "reason"],
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "provider_credential_set"},
                        "risk_class": {"const": "secret_ingress"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "action": {"const": "set"},
                                "generation": {"type": "integer", "exclusiveMinimum": 0},
                                "outcome": {"enum": ["active", "local_only", "stored"]},
                            },
                            "required": ["action", "generation", "outcome"],
                            "additionalProperties": False,
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "provider_credential_rotate"},
                        "risk_class": {"const": "secret_ingress"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "action": {"const": "rotate"},
                                "generation": {"type": "integer", "exclusiveMinimum": 0},
                                "outcome": {"enum": ["active", "local_only", "stored"]},
                            },
                            "required": ["action", "generation", "outcome"],
                            "additionalProperties": False,
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "repository_privacy_grant"},
                        "risk_class": {"const": "privacy_widen"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "recipe": {
                                    "enum": [
                                        "assisted_review",
                                        "expanded_review",
                                        "private",
                                        "metadata_only",
                                    ]
                                },
                                "outcome": {"enum": ["granted", "tightened"]},
                            },
                            "required": ["recipe", "outcome"],
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "project_coordination_grant"},
                        "risk_class": {"const": "privacy_widen"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "project_id": {
                                    "pattern": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                                    "type": "string",
                                },
                                "membership_generation": {
                                    "pattern": r"^[1-9][0-9]*$",
                                    "type": "string",
                                },
                                "audit_record_id": {
                                    "pattern": r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                                    "type": "string",
                                },
                                "outcome": {"const": "granted"},
                            },
                            "required": [
                                "audit_record_id",
                                "membership_generation",
                                "outcome",
                                "project_id",
                            ],
                            "additionalProperties": False,
                        },
                    }
                },
                {
                    "properties": {
                        "operation": {"const": "import_publication"},
                        "risk_class": {"const": "review_only"},
                        "outcome": {"const": "completed"},
                        "result": {
                            "type": "object",
                            "properties": {
                                "authorization_target_digest": {
                                    "pattern": r"^sha256:[0-9a-f]{64}$",
                                    "type": "string",
                                },
                                "outcome": {"const": "authorized"},
                            },
                            "required": ["authorization_target_digest", "outcome"],
                            "additionalProperties": False,
                        },
                    }
                },
            ],
            "allOf": [
                {
                    "if": {"properties": {"operation": {"const": "vault_initialize"}}},
                    "then": {
                        "properties": {
                            "risk_class": {"const": "secret_ingress"},
                            "authority_channel": {
                                "enum": [
                                    "trusted_console_presence",
                                    "agent_attested_chat_instruction",
                                ]
                            },
                        }
                    },
                },
                {
                    "if": {"properties": {"operation": {"const": "vault_passphrase_rotate"}}},
                    "then": {
                        "properties": {
                            "risk_class": {"const": "secret_reauth"},
                            "authority_channel": {
                                "enum": [
                                    "trusted_console_presence",
                                    "agent_attested_chat_instruction",
                                ]
                            },
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "operation": {
                                "enum": [
                                    "provider_credential_set",
                                    "provider_credential_rotate",
                                ]
                            }
                        }
                    },
                    "then": {
                        "properties": {
                            "risk_class": {"const": "secret_ingress"},
                            "authority_channel": {
                                "enum": [
                                    "trusted_console_presence",
                                    "agent_attested_chat_instruction",
                                ]
                            },
                        }
                    },
                },
                {
                    "if": {"properties": {"operation": {"const": "repository_privacy_grant"}}},
                    "then": {
                        "properties": {
                            "risk_class": {"const": "privacy_widen"},
                            "authority_channel": {"const": "agent_attested_chat_instruction"},
                        }
                    },
                },
                {
                    "if": {"properties": {"operation": {"const": "project_coordination_grant"}}},
                    "then": {
                        "properties": {
                            "risk_class": {"const": "privacy_widen"},
                            "authority_channel": {"const": "agent_attested_chat_instruction"},
                        }
                    },
                },
                {
                    "if": {"properties": {"operation": {"const": "import_publication"}}},
                    "then": {
                        "properties": {
                            "risk_class": {"const": "review_only"},
                            "authority_channel": {
                                "enum": [
                                    "trusted_console_presence",
                                    "agent_attested_chat_instruction",
                                ]
                            },
                        }
                    },
                },
            ],
        },
    )

    schema_: Literal["yoetz.elevated-bootstrap.result/6", "yoetz.elevated-bootstrap.result/7"] = (
        Field(alias="schema")
    )
    pending_id: PendingId
    operation: ConsentOperation
    risk_class: RiskClass
    outcome: Literal["completed", "denied"]
    danger_digest: Digest
    authority_channel: Literal["trusted_console_presence", "agent_attested_chat_instruction"]
    result: (
        ConsentDeniedResultModel
        | ConsentVaultInitializedResultModel
        | ConsentProviderCredentialResultModel
        | ConsentRepositoryPrivacyGrantResultModel
        | ConsentProjectCoordinationGrantResultModel
        | ConsentImportPublicationResultModel
    )

    @model_validator(mode="after")
    def _bind_result_to_operation_and_outcome(self) -> Self:
        if self.operation not in {
            "vault_initialize",
            "vault_passphrase_rotate",
            "provider_credential_set",
            "provider_credential_rotate",
            "repository_privacy_grant",
            "project_coordination_grant",
            "import_publication",
        }:
            raise ValueError("review_operation_not_implemented")
        expected_risk = {
            "repository_privacy_grant": "privacy_widen",
            "project_coordination_grant": "privacy_widen",
            "import_publication": "review_only",
            "vault_passphrase_rotate": "secret_reauth",
        }.get(self.operation, "secret_ingress")
        if self.risk_class != expected_risk:
            raise ValueError("review_risk_class_mismatch")
        if self.authority_channel == "agent_attested_chat_instruction" and self.operation not in {
            "vault_initialize",
            "vault_passphrase_rotate",
            "provider_credential_set",
            "provider_credential_rotate",
            "repository_privacy_grant",
            "project_coordination_grant",
            "import_publication",
        }:
            raise ValueError("review_authority_channel_mismatch")
        if (
            self.operation == "repository_privacy_grant"
            and self.authority_channel != "agent_attested_chat_instruction"
        ):
            raise ValueError("review_authority_channel_mismatch")
        if (
            self.operation == "project_coordination_grant"
            and self.authority_channel != "agent_attested_chat_instruction"
        ):
            raise ValueError("review_authority_channel_mismatch")
        if self.outcome == "denied":
            if type(self.result) is not ConsentDeniedResultModel:
                raise ValueError("review_result_outcome_mismatch")
            return self
        if self.operation in {"vault_initialize", "vault_passphrase_rotate"}:
            if type(self.result) is not ConsentVaultInitializedResultModel:
                raise ValueError("review_result_operation_mismatch")
            return self
        if self.operation == "repository_privacy_grant":
            if type(self.result) is not ConsentRepositoryPrivacyGrantResultModel:
                raise ValueError("review_result_operation_mismatch")
            if self.result.outcome == "denied":
                raise ValueError("review_result_outcome_mismatch")
            return self
        if self.operation == "project_coordination_grant":
            if type(self.result) is not ConsentProjectCoordinationGrantResultModel:
                raise ValueError("review_result_operation_mismatch")
            return self
        if self.operation == "import_publication":
            if type(self.result) is not ConsentImportPublicationResultModel:
                raise ValueError("review_result_operation_mismatch")
            return self
        if type(self.result) is not ConsentProviderCredentialResultModel:
            raise ValueError("review_result_operation_mismatch")
        expected_action = "set" if self.operation == "provider_credential_set" else "rotate"
        if self.result.action != expected_action:
            raise ValueError("review_result_action_mismatch")
        return self
