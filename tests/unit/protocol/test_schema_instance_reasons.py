"""A nested schema failure must carry the class of the mistake, and only closed tokens.

`SchemaInstanceInvalid` is the one channel by which a jsonschema verdict reaches the MCP error
projection. Before issue #240 it carried a path and nothing else, so every nested failure arrived
as one generic token and the branch scoring answered with a const from a family the caller never
selected.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from finishup.protocol.schemas import (
    SchemaInstanceInvalid,
    _best_schema_instance_error,  # pyright: ignore[reportPrivateUsage]
    _project_selected_one_of_required_locations,  # pyright: ignore[reportPrivateUsage]
)

_DISCRIMINATED_UNION: dict[str, Any] = {
    "type": "object",
    "oneOf": [
        {
            "properties": {
                "schema": {
                    "type": "object",
                    "properties": {"name": {"const": "alpha"}},
                    "required": ["name"],
                },
                "payload": {
                    "type": "object",
                    "properties": {"alpha_key": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            "required": ["schema", "payload"],
        },
        {
            "properties": {
                "schema": {
                    "type": "object",
                    "properties": {"name": {"const": "beta"}},
                    "required": ["name"],
                },
                "payload": {
                    "type": "object",
                    "properties": {"beta_key": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            "required": ["schema", "payload"],
        },
        {
            "properties": {
                "schema": {
                    "type": "object",
                    "properties": {"name": {"const": "gamma"}},
                    "required": ["name"],
                },
                "payload": {
                    "type": "object",
                    "properties": {"gamma_key": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            "required": ["schema", "payload"],
        },
        {
            "properties": {
                "schema": {
                    "type": "object",
                    "not": {"required": ["name"]},
                }
            }
        },
    ],
}


def _failure(instance: dict[str, Any]) -> ValidationError:
    validator = Draft202012Validator(cast(Any, _DISCRIMINATED_UNION))
    with pytest.raises(ValidationError) as captured:
        cast(Any, validator).validate(instance)
    return captured.value


def test_schema_instance_invalid_rejects_an_unregistered_reason() -> None:
    with pytest.raises(TypeError):
        SchemaInstanceInvalid((), reason="anything_else")


def test_schema_instance_invalid_rejects_an_out_of_range_count() -> None:
    with pytest.raises(TypeError):
        SchemaInstanceInvalid(("payload",), unknown_count=34)


def test_schema_instance_invalid_rejects_a_free_form_family() -> None:
    with pytest.raises(TypeError):
        SchemaInstanceInvalid(("payload",), family="Not A Family")


@pytest.mark.parametrize("version", ["1.0", "v1.0.0", "01.0.0", "1.0.0-rc1", "", "latest"])
def test_schema_instance_invalid_rejects_a_free_form_family_version(version: str) -> None:
    """The version names a frozen contract, so only an exact semantic triple is admitted."""

    with pytest.raises(TypeError):
        SchemaInstanceInvalid(("payload",), family="beta", family_version=version)


def test_schema_instance_invalid_defaults_stay_silent() -> None:
    error = SchemaInstanceInvalid(("payload",))

    assert error.reason is None
    assert error.family is None
    assert error.family_version is None
    assert error.unknown_count == 0


def test_discriminated_branch_selection_prefers_the_matched_family() -> None:
    """An unknown key inside the selected branch beats consts from branches never chosen."""

    best = _best_schema_instance_error(
        _failure({"schema": {"name": "beta"}, "payload": {"beta_key": "x", "unknown_key": "y"}})
    )

    assert best.validator == "additionalProperties"
    assert list(best.absolute_path) == ["payload"]


def test_an_unresolvable_discriminator_keeps_whole_tree_scoring() -> None:
    """With no branch selected the family itself is wrong, and the const is the right answer."""

    best = _best_schema_instance_error(
        _failure({"schema": {"name": 42}, "payload": {"unknown_key": "y"}})
    )

    assert best.validator == "const"
    assert list(best.absolute_path) == ["schema", "name"]


def test_an_undiscriminated_union_keeps_whole_tree_scoring() -> None:
    """The restriction is for const-discriminated unions only; every request model shares it."""

    schema: dict[str, Any] = {
        "oneOf": [
            {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]},
            {"type": "object", "properties": {"b": {"type": "string"}}, "required": ["b"]},
        ]
    }
    validator = Draft202012Validator(cast(Any, schema))
    with pytest.raises(ValidationError) as captured:
        cast(Any, validator).validate({"a": 1})

    best = _best_schema_instance_error(captured.value)

    assert best.validator in {"oneOf", "type", "required"}


def test_const_free_branch_remains_live_beside_matching_const_branch() -> None:
    """Projection must not select a const branch while a const-free alternative also survives."""

    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "kind": {"type": "string"},
            "alpha_peer": {"type": "string"},
            "fallback_peer": {"type": "string"},
        },
        "oneOf": [
            {"properties": {"kind": {"const": "alpha"}}, "required": ["alpha_peer"]},
            {"properties": {"kind": {"const": "beta"}}, "required": ["beta_peer"]},
            {"properties": {"kind": {"const": "gamma"}}, "required": ["gamma_peer"]},
            {"required": ["fallback_peer"]},
        ],
    }
    validator = Draft202012Validator(cast(Any, schema))
    with pytest.raises(ValidationError) as captured:
        cast(Any, validator).validate({"kind": "alpha"})

    assert _project_selected_one_of_required_locations(captured.value) is None


def test_fully_const_discriminated_union_still_projects_the_selected_peer() -> None:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {"kind": {"type": "string"}, "alpha_peer": {"type": "string"}},
        "oneOf": [
            {"properties": {"kind": {"const": "alpha"}}, "required": ["alpha_peer"]},
            {"properties": {"kind": {"const": "beta"}}, "required": ["beta_peer"]},
            {"properties": {"kind": {"const": "gamma"}}, "required": ["gamma_peer"]},
        ],
    }
    validator = Draft202012Validator(cast(Any, schema))
    with pytest.raises(ValidationError) as captured:
        cast(Any, validator).validate({"kind": "alpha"})

    projected = _project_selected_one_of_required_locations(captured.value)
    assert projected is not None
    assert projected[:3] == (((("alpha_peer",), "conditional_field_required"),), "kind", "alpha")
