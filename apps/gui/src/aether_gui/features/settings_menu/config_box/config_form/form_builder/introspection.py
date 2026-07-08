from __future__ import annotations

from collections.abc import Iterator
from types import UnionType
from typing import Any, TypedDict, Union, get_args, get_origin

from pydantic import BaseModel

from .resolved_field import ResolvedField


class Unwrapped(TypedDict):
    """An annotation stripped of ``| None``, with whether it was optional."""

    field_type: Any
    optional: bool


def iter_fields(model_cls: type[BaseModel], data: dict[str, Any] | None) -> Iterator[ResolvedField]:
    """Yield each field of ``model_cls`` resolved against the seed ``data``."""
    data = data or {}
    for name, info in model_cls.model_fields.items():
        unwrapped = _unwrap_optional(info.annotation)
        yield ResolvedField(
            name=name,
            info=info,
            field_type=unwrapped["field_type"],
            optional=unwrapped["optional"],
            value=data.get(name),
            title=info.title or name,
            description=info.description or "",
        )


def _unwrap_optional(annotation: Any) -> Unwrapped:
    """Strip ``X | None`` to ``X`` and report whether the field was optional."""
    if get_origin(annotation) not in (UnionType, Union):
        return {"field_type": annotation, "optional": False}
    args = get_args(annotation)
    optional = type(None) in args
    non_none = [arg for arg in args if arg is not type(None)]
    if len(non_none) != 1:
        return {"field_type": annotation, "optional": optional}
    return {"field_type": non_none[0], "optional": optional}
