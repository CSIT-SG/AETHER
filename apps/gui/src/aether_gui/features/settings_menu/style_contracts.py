"""QSS-facing names and dynamic-property values for settings menu widgets."""

from __future__ import annotations

from enum import StrEnum

# Widget object names used by QSS.
SETTINGS_SEARCH_OBJECT_NAME = "SettingsSearch"
SETTINGS_COUNT_OBJECT_NAME = "SettingsCount"
JSON_BACK_OBJECT_NAME = "JsonBack"
JSON_TOGGLE_OBJECT_NAME = "JsonToggle"
SETTINGS_NAV_OBJECT_NAME = "SettingsNav"
SETTINGS_JSON_OBJECT_NAME = "SettingsJson"

# Dynamic property names and values used by QSS.
SETTINGS_ROLE_PROPERTY = "settingsRole"
MESSAGE_STATE_PROPERTY = "messageState"
SECTION_ROLE = "section"
TITLE_ROLE = "title"
DESCRIPTION_ROLE = "description"


class MessageState(StrEnum):
    """Status states for the settings message line; values match QSS selectors."""

    NONE = "none"
    ERROR = "error"
    SUCCESS = "success"
