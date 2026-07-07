"""Choose concrete field widgets for resolved schema fields."""

from __future__ import annotations

import json

from aether_gui.features.settings_menu.json_object import JSON_INDENT
from pydantic.fields import FieldInfo

from ..fields import BoolField, FieldWidget, JsonField, StringField
from .resolved_field import ResolvedField
from .schema import SECRET_FIELD_NAMES


def make_leaf_field(field: ResolvedField) -> FieldWidget:
    """Build the right control for a single non-model field."""
    placeholder = _example_placeholder(field.info)
    if field.field_type is bool:
        return BoolField(field.title, field.description, field.value)
    if field.field_type is str:
        return StringField(
            field.title,
            field.description,
            field.value,
            optional=field.optional,
            secret=field.name in SECRET_FIELD_NAMES,
            placeholder=placeholder,
        )
    # dict fields and any unrecognized annotation fall back to JSON editing.
    return JsonField(
        field.title, field.description, field.value, optional=field.optional, placeholder=placeholder
    )


def _example_placeholder(info: FieldInfo) -> str:
    """Render a field's first declared example as placeholder text, if any."""
    if not info.examples:
        return ""
    example = info.examples[0]
    if isinstance(example, str):
        return example
    return json.dumps(example, indent=JSON_INDENT)
