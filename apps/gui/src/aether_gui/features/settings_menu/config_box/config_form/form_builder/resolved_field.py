"""Pydantic field descriptor consumed by the form builder."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any

from aether_gui.features.settings_menu.formatting import format_field_title
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
    description: str

    @property
    def title(self) -> str:
        """Human-readable title derived from the field name."""
        return format_field_title(self.name)

    @property
    def is_model(self) -> bool:
        return inspect.isclass(self.field_type) and issubclass(self.field_type, BaseModel)
