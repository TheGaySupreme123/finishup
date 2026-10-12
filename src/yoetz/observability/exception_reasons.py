"""Closed, reviewed exception-class reason vocabulary shared by every diagnostic sink.

Kept import-light (no configuration or pydantic models) so the latency-bound hook path can
classify an unexpected exception without loading the service logging stack (tb4n2 N-3).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

__all__ = [
    "EXCEPTION_REASONS",
    "EXCEPTION_REASON_TOKENS",
    "UNKNOWN_EXCEPTION_REASON",
    "exception_reason",
]

UNKNOWN_EXCEPTION_REASON: Final = "exception_unavailable"
# Closed reviewed registry of exception-class names that may identify an internal failure. Every
# token is a fixed literal; an unlisted class collapses to the sentinel so no class name a caller
# can influence is ever rendered. Storage/authorizer entries carry the durability failures that
# reach the daemon's unexpected-dispatch path.
EXCEPTION_REASONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ArithmeticError": "exception_arithmetic_error",
        "AssertionError": "exception_assertion_error",
        "AttributeError": "exception_attribute_error",
        "AuthError": "exception_auth_error",
        "BlockingIOError": "exception_blocking_io_error",
        "BrokenPipeError": "exception_broken_pipe_error",
        "BusyError": "exception_busy_error",
        "CantOpenError": "exception_cant_open_error",
        "ConfigError": "exception_config_error",
        "ConnectionError": "exception_connection_error",
        "ConnectionRefusedError": "exception_connection_refused_error",
        "ConnectionResetError": "exception_connection_reset_error",
        "ConstraintError": "exception_constraint_error",
        "ControlError": "exception_control_error",
        "ControlProtocolError": "exception_control_protocol_error",
        # Coordination domain and project command failures are ValueError subclasses that can
        # reach the status boundary from a project read (issue #840).
        "CoordinationError": "exception_coordination_error",
        "CorruptError": "exception_corrupt_error",
        "EOFError": "exception_eof_error",
        "FileExistsError": "exception_file_exists_error",
        "FileNotFoundError": "exception_file_not_found_error",
        "FullError": "exception_full_error",
        "HostLineageRegistryError": "exception_host_lineage_registry_error",
        "IndexError": "exception_index_error",
        "InterruptedError": "exception_interrupted_error",
        "IsADirectoryError": "exception_is_a_directory_error",
        "KeyError": "exception_key_error",
        "LifecycleError": "exception_lifecycle_error",
        "LookupError": "exception_lookup_error",
        "MemoryError": "exception_memory_error",
        "MisuseError": "exception_misuse_error",
        "NotADBError": "exception_not_a_db_error",
        "NotADirectoryError": "exception_not_a_directory_error",
        "NotImplementedError": "exception_not_implemented_error",
        "OSError": "exception_os_error",
        "OverflowError": "exception_overflow_error",
        "PathSafetyError": "exception_path_safety_error",
        "PermissionError": "exception_permission_error",
        "ProjectCommandError": "exception_project_command_error",
        "ProtocolValueError": "exception_protocol_value_error",
        "PublicOperationError": "exception_public_operation_error",
        "ReadOnlyError": "exception_read_only_error",
        "RecursionError": "exception_recursion_error",
        "ReferenceError": "exception_reference_error",
        "RuntimeError": "exception_runtime_error",
        "SQLError": "exception_sql_error",
        "StopAsyncIteration": "exception_stop_async_iteration",
        "StopIteration": "exception_stop_iteration",
        "StorageUnsafeError": "exception_storage_unsafe_error",
        "SystemError": "exception_system_error",
        "ThreadingViolationError": "exception_threading_violation_error",
        "TimeoutError": "exception_timeout_error",
        "TypeError": "exception_type_error",
        "UnicodeDecodeError": "exception_unicode_decode_error",
        "UnicodeEncodeError": "exception_unicode_encode_error",
        "ValidationError": "exception_validation_error",
        "ValueError": "exception_value_error",
        "ZeroDivisionError": "exception_zero_division_error",
    }
)
# Every token ``exception_reason`` can return, for consumers that admit them into a closed set.
EXCEPTION_REASON_TOKENS: Final = frozenset({*EXCEPTION_REASONS.values(), UNKNOWN_EXCEPTION_REASON})


def exception_reason(exc: BaseException) -> str:
    """Return a reviewed structural exception identity without formatting the exception."""

    # Deriving the token from the class name would let a dynamically created exception class carry
    # caller data onto stderr, so only these reviewed names ever resolve to a reason.
    try:
        name = type(exc).__name__
    except BaseException:
        return UNKNOWN_EXCEPTION_REASON
    return EXCEPTION_REASONS.get(name, UNKNOWN_EXCEPTION_REASON)
