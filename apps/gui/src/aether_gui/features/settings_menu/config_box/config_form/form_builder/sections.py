"""Qt section widgets used by the settings form builder."""

from __future__ import annotations

from aether_gui.features.settings_menu.style_contracts import (
    DESCRIPTION_ROLE,
    SECTION_ROLE,
    SETTINGS_ROLE_PROPERTY,
)
from PySide6 import QtWidgets


def section_group(title: str) -> QtWidgets.QGroupBox:
    """Build a settings section group tagged for QSS title styling."""
    group = QtWidgets.QGroupBox(title)
    group.setProperty(SETTINGS_ROLE_PROPERTY, SECTION_ROLE)
    return group


def section_header(description: str) -> QtWidgets.QLabel:
    """Build a wrapping, muted description label shown under a section title."""
    label = QtWidgets.QLabel(description)
    label.setProperty(SETTINGS_ROLE_PROPERTY, DESCRIPTION_ROLE)
    label.setWordWrap(True)
    return label
