"""Choose concrete field widgets for resolved schema fields."""

from __future__ import annotations

import json

from pydantic.fields import FieldInfo

from ....constants import JSON_INDENT, SECRET_FIELD_NAMES
from ..fields import BoolField, FieldWidget, JsonField, StringField
from .resolved_field import ResolvedField


def make_leaf_field(fld: ResolvedField) -> FieldWidget:
    """Build the right control for a single non-model field."""
    placeholder = _example_placeholder(fld.info)
    if fld.base is bool:
        return BoolField(fld.title, fld.description, fld.value)
    if fld.base is str:
        return StringField(
            fld.title,
            fld.description,
            fld.value,
            optional=fld.optional,
            secret=fld.name in SECRET_FIELD_NAMES,
            placeholder=placeholder,
        )
    # dict fields and any unrecognized annotation fall back to JSON editing.
    return JsonField(
        fld.title, fld.description, fld.value, optional=fld.optional, placeholder=placeholder
    )


def _example_placeholder(info: FieldInfo) -> str:
    """Render a field's first declared example as placeholder text, if any."""
    if not info.examples:
        return ""
    example = info.examples[0]
    if isinstance(example, str):
        return example
    return json.dumps(example, indent=JSON_INDENT)
