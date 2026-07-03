"""Constants shared by the settings menu feature."""

# Json Editing.
JSON_INDENT = 2
JSON_SORT_KEYS = True

# Logger names.
SETTINGS_MENU_LOGGER = "settings_menu"
CONFIG_SAVE_LOGGER = "json_loader"

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
MESSAGE_STATE_NONE = "none"
MESSAGE_STATE_ERROR = "error"
MESSAGE_STATE_SUCCESS = "success"

# Builder/schema labels.
GENERAL_CATEGORY = "General"
SECRET_FIELD_NAMES = frozenset({"api_key"})
FIELD_TITLE_ACRONYMS = {"url": "URL", "tls": "TLS", "ai": "AI", "api": "API", "id": "ID"}
