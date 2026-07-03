"""Pydantic field descriptor consumed by the form builder."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel
from pydantic.fields import FieldInfo


@dataclass
class ResolvedField:
    """A single pydantic field resolved into the bits the builder needs."""

    name: str
    info: FieldInfo
    field_type: Any  # annotation with ``| None`` stripped off
    optional: bool
    value: Any
    title: str
    description: str

    @property
    def is_model(self) -> bool:
        return inspect.isclass(self.field_type) and issubclass(self.field_type, BaseModel)
