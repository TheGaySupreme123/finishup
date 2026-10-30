"""Hermetic service-start configuration loading and source precedence."""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import ValidationError

from finishup.config.env import ENV_PREFIXES, EnvNameConflictError, canonical_env_name, read_env
from finishup.config.models import ConfigError, FinishUpConfig
from finishup.config.paths import config_file_path
from finishup.legacy_names import ENV_PREFIX

__all__ = [
    "ENV_PREFIX",
    "MinimalConfig",
    "default_config_file_path",
    "environment_config_path",
    "load_config",
    "parse_minimal_safe_config",
    "validate_config_mapping",
]

_MAX_CONFIG_BYTES: Final = 65_536
# Anchored to the message end: a quoted key may contain the same words earlier in the text.
_TOML_POSITION: Final = re.compile(r"\(at line ([0-9]+), column ([0-9]+)\)\Z")
_TOML_AT_END: Final = re.compile(r"\(at end of document\)\Z")
_INTEGER = re.compile(r"^-?[0-9]+$", re.ASCII)
_SECRET_TOKENS: Final = ("api_key", "apikey", "token", "secret", "password")
_VCS_MARKERS: Final = frozenset({".git", ".hg", ".svn", ".jj"})

type _LeafPath = tuple[str, ...]

# Every name below is also accepted under its legacy ``YOETZ_`` spelling (ADR-048), checked
# against this same allowlist: a legacy name is read only when its ``FINISHUP_`` twin is unset,
# and the two set to different values is ``config_env_conflict``.
_ENV_TO_LEAF: Final[dict[str, _LeafPath | None]] = {
    "FINISHUP_CONFIG": None,
    # Documented presentation control, recognized here so strict config loading cannot mistake
    # the prompt-loop opt-out for a service setting. It maps to no configuration leaf.
    "FINISHUP_TUI": None,
    # The one supported exact-target isolation contract (issue #518). It is consumed and
    # fail-closed validated by finishup.config.paths, which rebases every identity root (config,
    # storage bundle, state, runtime endpoints, cache, logs) onto the isolation root. It maps to
    # no configuration leaf; recognizing it here keeps strict config loading from rejecting an
    # isolated runtime as carrying an unknown FINISHUP_ variable.
    "FINISHUP_ISOLATED_ROOT": None,
    "FINISHUP_PROFILE": ("profile",),
    "FINISHUP_STORAGE_DATA_DIR": ("storage", "data_dir"),
    "FINISHUP_STORAGE_DURABILITY": ("storage", "durability"),
    "FINISHUP_VERIFICATION_SEMANTIC": ("verification", "semantic"),
    "FINISHUP_VERIFICATION_MAX_FINDINGS": ("verification", "max_findings"),
    "FINISHUP_VERIFICATION_FINDING_ATTEMPT_BUDGET": ("verification", "finding_attempt_budget"),
    "FINISHUP_LINEAGE_START_LEASE_SECONDS": ("lineage", "start_lease_seconds"),
    "FINISHUP_LINEAGE_ATTACH_HANDLE_TTL_SECONDS": ("lineage", "attach_handle_ttl_seconds"),
    "FINISHUP_LINEAGE_CONTACT_LOST_RECOVERY_SECONDS": (
        "lineage",
        "contact_lost_recovery_seconds",
    ),
    "FINISHUP_LINEAGE_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS": (
        "lineage",
        "top_level_contact_lost_horizon_seconds",
    ),
    "FINISHUP_LINEAGE_MAX_DECLARED_QUIET_SECONDS": ("lineage", "max_declared_quiet_seconds"),
    "FINISHUP_LINEAGE_MAX_DEPTH": ("lineage", "max_depth"),
    "FINISHUP_LINEAGE_MAX_FANOUT": ("lineage", "max_fanout"),
    "FINISHUP_LOG_LEVEL": ("logging", "level"),
    "FINISHUP_PROVIDER_ID": ("provider", "provider_id"),
    "FINISHUP_PROVIDER_ENDPOINT_PROFILE_ID": ("provider", "endpoint_profile_id"),
    "FINISHUP_PROVIDER_ENDPOINT_PROFILE_VERSION": (
        "provider",
        "endpoint_profile_version",
    ),
    "FINISHUP_PROVIDER_MODEL": ("provider", "model"),
    "FINISHUP_PROVIDER_TIMEOUT_SECONDS": ("provider", "timeout_seconds"),
    # MCP bridge-to-service deadlines, read by ``finishup.mcp.server``; they map to no
    # configuration leaf. Recognizing them keeps a documented override from making strict loading
    # in the bridge refuse the whole environment. One name per workflow tool, plus the default.
    "FINISHUP_MCP_DEADLINE_MS": None,
    "FINISHUP_MCP_DEADLINE_MS_CHECK": None,
    "FINISHUP_MCP_DEADLINE_MS_PUBLISH_WORK": None,
    "FINISHUP_MCP_DEADLINE_MS_RECEIPT": None,
    "FINISHUP_MCP_DEADLINE_MS_RESPOND": None,
    "FINISHUP_MCP_DEADLINE_MS_START": None,
    "FINISHUP_MCP_DEADLINE_MS_STATUS": None,
}
_OVERRIDE_TO_LEAF: Final[dict[str, _LeafPath | None]] = {
    "config": None,
    "profile": ("profile",),
    "storage.data_dir": ("storage", "data_dir"),
    "storage.durability": ("storage", "durability"),
    "verification.semantic": ("verification", "semantic"),
    "verification.max_findings": ("verification", "max_findings"),
    "verification.finding_attempt_budget": ("verification", "finding_attempt_budget"),
    "lineage.start_lease_seconds": ("lineage", "start_lease_seconds"),
    "lineage.attach_handle_ttl_seconds": ("lineage", "attach_handle_ttl_seconds"),
    "lineage.contact_lost_recovery_seconds": ("lineage", "contact_lost_recovery_seconds"),
    "lineage.top_level_contact_lost_horizon_seconds": (
        "lineage",
        "top_level_contact_lost_horizon_seconds",
    ),
    "lineage.max_declared_quiet_seconds": ("lineage", "max_declared_quiet_seconds"),
    "lineage.max_depth": ("lineage", "max_depth"),
    "lineage.max_fanout": ("lineage", "max_fanout"),
    "logging.level": ("logging", "level"),
    "provider.provider_id": ("provider", "provider_id"),
    "provider.endpoint_profile_id": ("provider", "endpoint_profile_id"),
    "provider.endpoint_profile_version": ("provider", "endpoint_profile_version"),
    "provider.model": ("provider", "model"),
    "provider.timeout_seconds": ("provider", "timeout_seconds"),
}
_INTEGER_LEAVES: Final = frozenset(
    {
        ("verification", "max_findings"),
        ("verification", "finding_attempt_budget"),
        ("lineage", "start_lease_seconds"),
        ("lineage", "attach_handle_ttl_seconds"),
        ("lineage", "contact_lost_recovery_seconds"),
        ("lineage", "top_level_contact_lost_horizon_seconds"),
        ("lineage", "max_declared_quiet_seconds"),
        ("lineage", "max_depth"),
        ("lineage", "max_fanout"),
        ("provider", "timeout_seconds"),
    }
)
_PATH_LEAVES: Final = frozenset({("storage", "data_dir")})
_PROFILES: Final = frozenset(
    {"strict-local", "local-openai", "codex-subscription", "test-fake", "release-probe"}
)
_LOG_LEVELS: Final = frozenset({"debug", "info", "warning", "error"})


@dataclass(frozen=True, slots=True)
class MinimalConfig:
    profile: Literal[
        "strict-local", "local-openai", "codex-subscription", "test-fake", "release-probe"
    ]
    data_dir: Path | None
    log_level: Literal["debug", "info", "warning", "error"]
    config_path_used: Path | None

    def __post_init__(self) -> None:
        if self.profile not in _PROFILES:
            raise ConfigError("config_value_invalid")
        if self.log_level not in _LOG_LEVELS:
            raise ConfigError("config_value_invalid")


def default_config_file_path() -> Path:
    """Return the sole platform-native default config path."""

    return config_file_path()


def environment_config_path(env: Mapping[str, str] | None = None) -> Path | None:
    """Return the config file ``FINISHUP_CONFIG`` names, or ``None`` when it names none.

    The legacy ``YOETZ_CONFIG`` spelling is read when ``FINISHUP_CONFIG`` is unset (ADR-048);
    the two set to different values is ``config_env_conflict``.
    """

    try:
        selected = read_env("CONFIG", env)
    except EnvNameConflictError as exc:
        raise ConfigError("config_env_conflict", safe_name=exc.name) from None
    return Path(selected) if selected else None


def _key_names(mapping: Mapping[str, str]) -> tuple[str, ...]:
    try:
        raw = tuple(mapping.keys())
    except Exception as exc:
        raise ConfigError("config_value_invalid") from exc
    if any(type(key) is not str for key in raw):
        raise ConfigError("config_value_invalid")
    return tuple(sorted(raw))


def _secret_name(name: str) -> bool:
    return any(token in name.casefold() for token in _SECRET_TOKENS)


def _validated_source_values(
    source: Mapping[str, str],
    *,
    names: Mapping[str, _LeafPath | None],
    prefix_only: bool,
) -> dict[str, str]:
    keys = _key_names(source)
    considered = tuple(key for key in keys if not prefix_only or key.startswith(ENV_PREFIXES))
    secret = tuple(key for key in considered if _secret_name(key))
    if secret:
        reason = "secret_env_forbidden" if prefix_only else "secret_config_override_forbidden"
        raise ConfigError(reason, safe_name=secret[0][:256])
    unknown = tuple(key for key in considered if _source_name(key, prefix_only) not in names)
    if unknown:
        reason = "unknown_config_env_var" if prefix_only else "unknown_config_override"
        raise ConfigError(reason, safe_name=unknown[0][:256])

    values: dict[str, str] = {}
    for key in considered:
        try:
            value = source[key]
        except Exception as exc:
            raise ConfigError("config_value_invalid", safe_name=key[:256]) from exc
        if type(value) is not str:
            raise ConfigError("config_value_invalid", safe_name=key[:256])
        # A legacy ``YOETZ_`` name folds onto its ``FINISHUP_`` twin (ADR-048). The same value
        # under both is one setting; different values are ambiguous and refused.
        name = _source_name(key, prefix_only)
        if name in values and values[name] != value:
            raise ConfigError("config_env_conflict", safe_name=name[:256])
        values[name] = value
    return values


def _source_name(key: str, prefix_only: bool) -> str:
    """Return the allowlist spelling of one considered source key."""

    if not prefix_only:
        return key
    canonical = canonical_env_name(key)
    return key if canonical is None else canonical


def _selected_config_path(
    config_path: Path | None,
    env_values: Mapping[str, str],
    override_values: Mapping[str, str],
) -> tuple[Path, bool]:
    if config_path is not None:
        return config_path, True
    override = override_values.get("config", "")
    if override:
        return Path(override), True
    environment = env_values.get("FINISHUP_CONFIG", "")
    if environment:
        return Path(environment), True
    return default_config_file_path(), False


def _read_config(path: Path) -> tuple[dict[str, object], bool]:
    try:
        with path.open("rb") as source:
            data = source.read(_MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return {}, False
    except OSError as exc:
        raise ConfigError("config_file_unreadable") from exc
    if len(data) > _MAX_CONFIG_BYTES:
        raise ConfigError("config_file_too_large")
    try:
        document = data.decode("utf-8")
        parsed = tomllib.loads(document)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        line, column = _toml_error_position(exc, data)
        raise ConfigError(
            "config_toml_invalid",
            line=line if type(line) is int and line > 0 else None,
            column=column if type(column) is int and column > 0 else None,
        ) from None
    return cast(dict[str, object], parsed), True


def _toml_error_position(exc: Exception, data: bytes) -> tuple[object, object]:
    """Line and column of a TOML error, as integers only.

    Python 3.14 exposes ``lineno``/``colno``; before that (the 3.12 floor, issue #1119) only the
    message ends with ``(at line N, column M)`` or ``(at end of document)``, the latter computed
    from the document as 3.14 does. Only the two integers leave this function.
    """

    line = getattr(exc, "lineno", None)
    column = getattr(exc, "colno", None)
    if line is None and isinstance(exc, tomllib.TOMLDecodeError):
        message = str(exc)
        found = _TOML_POSITION.search(message)
        if found is not None:
            line, column = int(found.group(1)), int(found.group(2))
        elif _TOML_AT_END.search(message) is not None:
            text = data.decode("utf-8")
            line = text.count("\n") + 1
            column = len(text.rsplit("\n", 1)[-1]) + 1
    return line, column


def _in_repository(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=False)
        return any(
            (ancestor / marker).exists()
            for ancestor in (resolved.parent, *resolved.parent.parents)
            for marker in _VCS_MARKERS
        )
    except OSError:
        return False


def _emit_explicit_project_config() -> None:
    sys.stderr.write('{"reason":"explicit_project_config"}\n')


def _mapping_section(source: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = source.get(name, {})
    if not isinstance(value, Mapping):
        raise ConfigError("config_value_invalid", safe_name=name)
    return cast(Mapping[str, object], value)


def _file_leaf(source: Mapping[str, object], leaf: _LeafPath) -> tuple[object, bool]:
    if len(leaf) == 1:
        return (source[leaf[0]], True) if leaf[0] in source else (None, False)
    section = _mapping_section(source, leaf[0])
    return (section[leaf[1]], True) if leaf[1] in section else (None, False)


def _parse_string_leaf(leaf: _LeafPath, value: str) -> object:
    if leaf in _INTEGER_LEAVES:
        if _INTEGER.fullmatch(value) is None:
            raise ConfigError("config_value_invalid")
        return int(value, 10)
    if leaf in _PATH_LEAVES:
        return Path(value)
    return value


def _set_leaf(target: dict[str, object], leaf: _LeafPath, value: object) -> None:
    if len(leaf) == 1:
        target[leaf[0]] = value
        return
    existing = target.get(leaf[0])
    if existing is None:
        section: dict[str, object] = {}
    elif isinstance(existing, Mapping):
        section = dict(cast(Mapping[str, object], existing))
    else:
        raise ConfigError("config_value_invalid", safe_name=leaf[0])
    section[leaf[1]] = value
    target[leaf[0]] = section


def _merge_selected(
    file_values: Mapping[str, object],
    env_values: Mapping[str, str],
    override_values: Mapping[str, str],
) -> dict[str, object]:
    merged = dict(file_values)
    for override_name, leaf in _OVERRIDE_TO_LEAF.items():
        if leaf is None:
            continue
        env_name = next(name for name, candidate in _ENV_TO_LEAF.items() if candidate == leaf)
        override = override_values.get(override_name, "")
        environment = env_values.get(env_name, "")
        if override:
            _set_leaf(merged, leaf, _parse_string_leaf(leaf, override))
        elif environment:
            _set_leaf(merged, leaf, _parse_string_leaf(leaf, environment))

    file_data_dir, present = _file_leaf(merged, ("storage", "data_dir"))
    if present and type(file_data_dir) is str:
        _set_leaf(merged, ("storage", "data_dir"), Path(file_data_dir))
    return merged


def _reject_file_release_probe(file_values: Mapping[str, object]) -> None:
    if file_values.get("profile") == "release-probe":
        raise ConfigError("release_probe_not_a_user_profile")


def validate_config_mapping(values: Mapping[str, object]) -> FinishUpConfig:
    """Normalize file-shape leaves and strictly validate one config mapping.

    This is the single canonical rule for turning parsed configuration data into a validated
    ``FinishUpConfig``: the file-shape ``storage.data_dir`` string becomes a ``Path`` before strict
    model validation, and every failure surfaces as a bounded ``ConfigError``. Writers use it as
    their round-trip check so a file FinishUP writes is, by construction, a file this loader
    accepts (#520).
    """

    merged = dict(values)
    data_dir, present = _file_leaf(merged, ("storage", "data_dir"))
    if present and type(data_dir) is str:
        _set_leaf(merged, ("storage", "data_dir"), Path(data_dir))
    try:
        return FinishUpConfig.model_validate(merged, strict=True)
    except ConfigError:
        raise
    except ValidationError as exc:
        raise ConfigError("config_value_invalid") from exc
    except Exception as exc:
        raise ConfigError("config_value_invalid") from exc


def load_config(
    service_overrides: Mapping[str, str],
    env: Mapping[str, str],
    config_path: Path | None,
) -> FinishUpConfig:
    """Load exactly one service config using leaf-wise trusted precedence."""

    env_values = _validated_source_values(env, names=_ENV_TO_LEAF, prefix_only=True)
    override_values = _validated_source_values(
        service_overrides, names=_OVERRIDE_TO_LEAF, prefix_only=False
    )
    selected_path, explicit = _selected_config_path(config_path, env_values, override_values)
    file_values, read = _read_config(selected_path)
    if read:
        _reject_file_release_probe(file_values)
        # Existing files with omitted leaves retain the released defaults. An upgrade or an
        # unrelated rewrite must not silently opt an existing installation into required review.
        for leaf, legacy in (("semantic", "optional"), ("max_findings", 3)):
            _, present = _file_leaf(file_values, ("verification", leaf))
            if not present:
                _set_leaf(file_values, ("verification", leaf), legacy)
    if explicit and read and _in_repository(selected_path):
        _emit_explicit_project_config()
    return validate_config_mapping(_merge_selected(file_values, env_values, override_values))


def _minimal_file_value(source: Mapping[str, object], leaf: _LeafPath, default: object) -> object:
    value, present = _file_leaf(source, leaf)
    return value if present else default


def parse_minimal_safe_config(
    env: Mapping[str, str], service_overrides: Mapping[str, str]
) -> MinimalConfig:
    """Tolerantly resolve the startup-safe profile, data path, and log level."""

    env_values = _validated_source_values(env, names=_ENV_TO_LEAF, prefix_only=True)
    override_values = _validated_source_values(
        service_overrides, names=_OVERRIDE_TO_LEAF, prefix_only=False
    )
    selected_path, explicit = _selected_config_path(None, env_values, override_values)
    file_values, read = _read_config(selected_path)
    if read:
        _reject_file_release_probe(file_values)
    if explicit and read and _in_repository(selected_path):
        _emit_explicit_project_config()

    profile: object = _minimal_file_value(file_values, ("profile",), "strict-local")
    env_profile = env_values.get("FINISHUP_PROFILE", "")
    override_profile = override_values.get("profile", "")
    if override_profile:
        profile = override_profile
    elif env_profile:
        profile = env_profile
    if type(profile) is not str or profile not in _PROFILES:
        raise ConfigError("config_value_invalid")

    data_dir: object = _minimal_file_value(file_values, ("storage", "data_dir"), None)
    env_data_dir = env_values.get("FINISHUP_STORAGE_DATA_DIR", "")
    override_data_dir = override_values.get("storage.data_dir", "")
    if override_data_dir:
        data_dir = Path(override_data_dir)
    elif env_data_dir:
        data_dir = Path(env_data_dir)
    elif type(data_dir) is str:
        data_dir = Path(data_dir)
    if data_dir is not None and not isinstance(data_dir, Path):
        raise ConfigError("config_value_invalid")

    log_level: object = _minimal_file_value(file_values, ("logging", "level"), "info")
    env_log = env_values.get("FINISHUP_LOG_LEVEL", "")
    override_log = override_values.get("logging.level", "")
    if override_log:
        log_level = override_log
    elif env_log:
        log_level = env_log
    if type(log_level) is not str or log_level not in _LOG_LEVELS:
        raise ConfigError("config_value_invalid")

    return MinimalConfig(
        profile=cast(
            Literal[
                "strict-local",
                "local-openai",
                "codex-subscription",
                "test-fake",
                "release-probe",
            ],
            profile,
        ),
        data_dir=data_dir,
        log_level=cast(Literal["debug", "info", "warning", "error"], log_level),
        config_path_used=selected_path if read else None,
    )
