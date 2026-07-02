"""Qt section widgets used by the settings form builder."""

from __future__ import annotations

from PySide6 import QtWidgets


def section_group(title: str) -> QtWidgets.QGroupBox:
    """Build a settings section group tagged for QSS title styling."""
    group = QtWidgets.QGroupBox(title)
    group.setProperty("settingsRole", "section")
    return group


def section_header(description: str) -> QtWidgets.QLabel:
    """Build a wrapping, muted description label shown under a section title."""
    label = QtWidgets.QLabel(description)
    label.setProperty("settingsRole", "description")
    label.setWordWrap(True)
    return label
