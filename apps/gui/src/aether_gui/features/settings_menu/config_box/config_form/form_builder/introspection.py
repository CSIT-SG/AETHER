from __future__ import annotations

from collections.abc import Iterator
from types import UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel

from .resolved_field import ResolvedField


def iter_fields(model_cls: type[BaseModel], data: dict[str, Any] | None) -> Iterator[ResolvedField]:
    """Yield each field of ``model_cls`` resolved against the seed ``data``."""
    data = data or {}
    for name, info in model_cls.model_fields.items():
        field_type, optional = _unwrap_optional(info.annotation)
        yield ResolvedField(
            name=name,
            info=info,
            field_type=field_type,
            optional=optional,
            value=data.get(name),
            description=info.description or "",
        )


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    """Strip ``X | None`` to ``(X, True)``; non-optional types return ``(X, False)``."""
    if get_origin(annotation) not in (UnionType, Union):
        return annotation, False
    args = get_args(annotation)
    optional = type(None) in args
    non_none = [arg for arg in args if arg is not type(None)]
    if len(non_none) != 1:
        return annotation, optional
    return non_none[0], optional
