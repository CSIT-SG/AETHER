from __future__ import annotations

import json

from aether_gui.utils.json_format import JSON_INDENT
from pydantic.fields import FieldInfo

from ..fields import ApiKeyField, BoolField, FieldWidget, JsonField, StringField
from .constants import SECRET_FIELD_NAMES
from .resolved_field import ResolvedField


def make_leaf_field(field: ResolvedField) -> FieldWidget:
    """Build the right control for a single non-model field."""
    # Prefer declared examples; otherwise optional fields show a greyed "null".
    example = _example_placeholder(field.info)
    placeholder = example or ("null" if field.optional else "")
    tab_example = example if not field.optional else ""
    if field.field_type is bool:
        return BoolField(field.title, field.description, field.value)
    if field.field_type is str:
        if field.name in SECRET_FIELD_NAMES:
            # The API key gets a masked field with show/hide plus a validity check.
            return ApiKeyField(
                field.title,
                field.description,
                field.value,
                optional=field.optional,
                required=not field.optional,
                placeholder=placeholder,
                example=tab_example,
            )
        return StringField(
            field.title,
            field.description,
            field.value,
            optional=field.optional,
            required=not field.optional,
            placeholder=placeholder,
            example=tab_example,
        )
    # dict fields and any unrecognized annotation fall back to JSON editing.
    return JsonField(
        field.title,
        field.description,
        field.value,
        optional=field.optional,
        required=not field.optional,
        placeholder=placeholder,
        example=tab_example,
    )


def _example_placeholder(info: FieldInfo) -> str:
    """Render a field's first declared example as placeholder text, if any."""
    if not info.examples:
        return ""
    example = info.examples[0]
    if isinstance(example, str):
        return example
    return json.dumps(example, indent=JSON_INDENT)
