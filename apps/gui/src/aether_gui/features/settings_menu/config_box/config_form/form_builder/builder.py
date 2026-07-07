from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel
from PySide6 import QtWidgets

from .field_factory import make_leaf_field
from .introspection import iter_fields
from .resolved_field import ResolvedField
from .schema import GENERAL_CATEGORY
from .sections import section_group, section_header
from .settings_form import Getter, SearchMeta, SettingsForm
from .values import make_getter


def build_settings_form(model_cls: type[BaseModel], data: dict[str, Any] | None) -> SettingsForm:
    """Build a categorized settings form for ``model_cls`` seeded with ``data``.

    Top-level scalar fields are gathered under a synthetic "General" section;
    each nested ``BaseModel`` field becomes its own titled section.

    Args:
        model_cls: The pydantic model to introspect.
        data: Current values (typically ``config.model_dump()``) to pre-fill.

    Returns:
        A :class:`SettingsForm` bundling the widget, value getter, ordered
        sections and searchable rows.
    """
    container = QtWidgets.QWidget()
    layout = QtWidgets.QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(12)

    rows: list[SearchMeta] = []
    # field name -> value-reader callable; bundled by make_getter at the end.
    val_getters: dict[str, Callable[[], Any]] = {}

    # "General" collects the config's root-level *non-model* keys, plain scalars that don't warrant a section of their own.
    # Each nested pydantic model (provider, tls, ...) becomes its own section.
    general_group = section_group(GENERAL_CATEGORY)
    general_layout = QtWidgets.QVBoxLayout(general_group)
    has_general = False
    model_sections: list[tuple[str, QtWidgets.QWidget]] = []

    for field in iter_fields(model_cls, data):
        if field.is_model:
            # Nested model -> its own titled section; its getter yields a nested dict.
            group, getter = _build_model_section(field, rows, field.title)
            val_getters[field.name] = getter
            model_sections.append((field.title, group))
        else:
            # Root-level scalar -> goes into the shared "General" section.
            _add_leaf(general_layout, val_getters, rows, field, GENERAL_CATEGORY)
            has_general = True

    # General first, then one section per nested model in declaration order.
    sections: list[tuple[str, QtWidgets.QWidget]] = []
    if has_general:
        sections.append((GENERAL_CATEGORY, general_group))
    sections.extend(model_sections)

    for _title, section_widget in sections:
        layout.addWidget(section_widget)
    layout.addStretch(1)

    # make_getter collapses the {name: value-reader} map into one callable that
    # rebuilds the whole nested config dict from the live widgets on demand.
    return SettingsForm(container, make_getter(val_getters), sections, rows)


def _build_model_section(
    field: ResolvedField, rows: list[SearchMeta], category: str
) -> tuple[QtWidgets.QGroupBox, Getter]:
    """Build a titled group box for a nested-model field and its children."""
    group = section_group(field.title)
    group_layout = QtWidgets.QVBoxLayout(group)
    group_layout.setSpacing(6)
    if field.description:
        group_layout.addWidget(section_header(field.description))

    data = field.value if isinstance(field.value, dict) else {}
    val_getters: dict[str, Callable[[], Any]] = {}
    for child_field in iter_fields(field.field_type, data):
        if child_field.is_model:
            child_group, getter = _build_model_section(child_field, rows, category)
            group_layout.addWidget(child_group)
            val_getters[child_field.name] = getter
        else:
            _add_leaf(group_layout, val_getters, rows, child_field, category)

    return group, make_getter(val_getters)


def _add_leaf(
    layout: QtWidgets.QVBoxLayout,
    val_getters: dict[str, Callable[[], Any]],
    rows: list[SearchMeta],
    field: ResolvedField,
    category: str,
) -> None:
    """Create a leaf control, add it to ``layout`` and register its value + search row."""
    field_widget = make_leaf_field(field)
    layout.addWidget(field_widget)
    val_getters[field.name] = field_widget.value
    rows.append(
        SearchMeta(
            search_text=f"{category} {field.title} {field.description} {field.name}".lower(),
            widget=field_widget,
            category=category,
        )
    )
