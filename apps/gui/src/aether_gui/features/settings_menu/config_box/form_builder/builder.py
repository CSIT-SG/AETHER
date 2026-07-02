"""Build the Qt settings form from resolved pydantic fields.

This stage knows about Qt widgets and layouts. It consumes
:class:`ResolvedField` values from :mod:`.introspection` and produces a
:class:`SettingsForm`. Functions are ordered top-down: the public entry point
first, then progressively lower-level helpers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel
from PySide6 import QtWidgets

from ..fields import BoolField, FieldWidget, JsonField, StringField
from .introspection import example_placeholder, iter_fields
from .types import GENERAL_CATEGORY, Getter, ResolvedField, Row, SettingsForm

# Fields whose text input should be masked.
_SECRET_FIELDS = {"api_key"}


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

    rows: list[Row] = []
    getters: dict[str, Callable[[], Any]] = {}

    general_group = QtWidgets.QGroupBox(GENERAL_CATEGORY)
    general_layout = QtWidgets.QVBoxLayout(general_group)
    has_general = False
    model_sections: list[tuple[str, QtWidgets.QWidget]] = []

    for fld in iter_fields(model_cls, data):
        if fld.is_model:
            group, getter = _build_model_section(fld, rows, fld.title)
            getters[fld.name] = getter
            model_sections.append((fld.title, group))
        else:
            _add_leaf(general_layout, getters, rows, fld, GENERAL_CATEGORY)
            has_general = True

    # General first, then one section per nested model in declaration order.
    sections: list[tuple[str, QtWidgets.QWidget]] = []
    if has_general:
        sections.append((GENERAL_CATEGORY, general_group))
    sections.extend(model_sections)

    for _title, section_widget in sections:
        layout.addWidget(section_widget)
    layout.addStretch(1)

    return SettingsForm(container, _make_getter(getters), sections, rows)


def _build_group_body(
    model_cls: type[BaseModel], data: dict[str, Any] | None, rows: list[Row], category: str
) -> tuple[QtWidgets.QWidget, Getter]:
    """Build the inner widget for a model's fields (without an outer group box)."""
    container = QtWidgets.QWidget()
    layout = QtWidgets.QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)

    getters: dict[str, Callable[[], Any]] = {}
    for fld in iter_fields(model_cls, data):
        if fld.is_model:
            group, getter = _build_model_section(fld, rows, category)
            layout.addWidget(group)
            getters[fld.name] = getter
        else:
            _add_leaf(layout, getters, rows, fld, category)

    return container, _make_getter(getters)


def _build_model_section(
    fld: ResolvedField, rows: list[Row], category: str
) -> tuple[QtWidgets.QGroupBox, Getter]:
    """Build a titled group box for a nested-model field."""
    group = QtWidgets.QGroupBox(fld.title)
    group_layout = QtWidgets.QVBoxLayout(group)
    if fld.description:
        group_layout.addWidget(_section_header(fld.description))
    body, getter = _build_group_body(
        fld.base, fld.value if isinstance(fld.value, dict) else {}, rows, category
    )
    group_layout.addWidget(body)
    return group, getter


def _add_leaf(
    layout: QtWidgets.QVBoxLayout,
    getters: dict[str, Callable[[], Any]],
    rows: list[Row],
    fld: ResolvedField,
    category: str,
) -> None:
    """Create a leaf control, add it to ``layout`` and register its value + search row."""
    widget = _make_leaf(fld)
    layout.addWidget(widget)
    getters[fld.name] = widget.value
    rows.append((f"{category} {fld.title} {fld.description} {fld.name}".lower(), widget, category))


def _make_leaf(fld: ResolvedField) -> FieldWidget:
    """Build the right control for a single (non-model) field."""
    placeholder = example_placeholder(fld.info)
    if fld.base is bool:
        return BoolField(fld.title, fld.description, fld.value)
    if fld.base is str:
        return StringField(
            fld.title,
            fld.description,
            fld.value,
            optional=fld.optional,
            secret=fld.name in _SECRET_FIELDS,
            placeholder=placeholder,
        )
    # dict fields and any unrecognized annotation fall back to JSON editing.
    return JsonField(
        fld.title, fld.description, fld.value, optional=fld.optional, placeholder=placeholder
    )


def _section_header(description: str) -> QtWidgets.QLabel:
    """A wrapping, muted description label shown under a section title."""
    label = QtWidgets.QLabel(description)
    label.setProperty("settingsRole", "description")
    label.setWordWrap(True)
    return label


def _make_getter(getters: dict[str, Callable[[], Any]]) -> Getter:
    """Bundle per-field value callables into a single nested-dict getter."""

    def getter() -> dict[str, Any]:
        return {name: get() for name, get in getters.items()}

    return getter
