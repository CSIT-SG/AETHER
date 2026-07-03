"""Resolve pydantic model fields into builder-friendly descriptors.

This stage knows about pydantic (annotations, ``FieldInfo``, examples) and nothing
about Qt. It turns each ``model_fields`` entry into a :class:`ResolvedField`.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel

from ....constants import EMPTY_TEXT, FIELD_TITLE_ACRONYMS
from .resolved_field import ResolvedField


def prettify(name: str) -> str:
    """Turn a snake_case field name into a human-readable title."""
    return " ".join(FIELD_TITLE_ACRONYMS.get(part, part.capitalize()) for part in name.split("_"))


def iter_fields(model_cls: type[BaseModel], data: dict[str, Any] | None) -> Iterator[ResolvedField]:
    """Yield each field of ``model_cls`` resolved against the seed ``data``."""
    data = data or {}
    for name, info in model_cls.model_fields.items():
        base, optional = _unwrap_optional(info.annotation)
        yield ResolvedField(
            name=name,
            info=info,
            base=base,
            optional=optional,
            value=data.get(name),
            title=prettify(name),
            description=info.description or EMPTY_TEXT,
        )


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    """Strip ``X | None`` to ``(X, True)``; non-optional types return ``(X, False)``."""
    if get_origin(annotation) in (UnionType, Union):
        args = get_args(annotation)
        optional = type(None) in args
        non_none = [arg for arg in args if arg is not type(None)]
        if len(non_none) == 1:
            return non_none[0], optional
        return annotation, optional
    return annotation, False
