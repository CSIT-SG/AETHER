"""Constants shared by the settings menu feature."""

from types import SimpleNamespace

# Dialog sizing and titles.
SETTINGS_DIALOG_TITLE = "AETHER Settings"
SETTINGS_DIALOG_INITIAL_SIZE = (900, 600)
SETTINGS_DIALOG_MINIMUM_SIZE = (700, 450)
CONFIG_BOX_MINIMUM_SIZE = (500, 200)

# Layout dimensions.
NO_MARGINS = (0, 0, 0, 0)
COMPACT_MARGINS = (2, 2, 2, 2)
MESSAGE_LABEL_MARGINS = (8, 0, 8, 0)
CONFIG_BOX_SPACING = 8
FORM_SECTION_SPACING = 12
FORM_GROUP_SPACING = 6
FIELD_MARGINS = (0, 6, 0, 6)
FIELD_SPACING = 4
SETTINGS_FORM_VIEW_SPACING = 8
SIDEBAR_WIDTH_RANGE = (150, 200)
SIDEBAR_ITEM_SPACING = 2
JSON_FIELD_HEIGHT_RANGE = (60, 160)

# QSS design tokens (border widths, radii, paddings, margins) injected into the
# settings components' jinja context via ``self.state["tokens"]`` so the
# ``.qss.jinja`` files reference this.
# Values are complete CSS strings, used as ``{{ tokens.<name> }}`` in templates.
STYLE_TOKENS = SimpleNamespace(
    border_width="1px",
    radius_input="4px",
    radius_section="6px",
    pad_input="4px",
    pad_search="6px 8px",
    pad_button="5px 10px",
    pad_count="0 6px",
    pad_group="8px",
    pad_title="0 4px",
    pad_nav_item="8px 12px",
    pad_nav_top="4px",
    margin_search="2px",
    margin_nav_item="3px 6px",
    margin_group_top="14px",
    title_left="10px",
)

# JSON formatting.
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

# User-facing button labels, tooltips, placeholders, and status text.
BACK_TO_SETTINGS_LABEL = "Back to Settings"
JSON_TOGGLE_LABEL = "{ } JSON"
SEARCH_PLACEHOLDER = "Search settings"
BACK_TO_SETTINGS_TOOLTIP = "Return to the settings form"
JSON_TOGGLE_TOOLTIP = "View and edit the raw settings JSON"
ENABLED_CHECKBOX_LABEL = "Enabled"
APPLY_BUTTON_LABEL = "Apply"
OK_BUTTON_LABEL = "Ok"
CANCEL_BUTTON_LABEL = "Cancel"
UNSET_BUTTON_LABEL = "I AM NOT SET"
SETTINGS_COUNT_TEXT = "{total} settings"
FILTERED_SETTINGS_COUNT_TEXT = "{visible} of {total} settings"
INVALID_CONFIG_MESSAGE = "Invalid config, check IDA output for more details"
CONFIG_APPLIED_MESSAGE = "Config applied!"

# Builder/schema labels.
GENERAL_CATEGORY = "General"
SECRET_FIELD_NAMES = frozenset({"api_key"})
FIELD_TITLE_ACRONYMS = {"url": "URL", "tls": "TLS", "ai": "AI", "api": "API", "id": "ID"}

# Empty values with domain meaning.
EMPTY_TEXT = ""
MESSAGE_CLEAR_TEXT = " "

# Developer-facing diagnostics.
INVALID_JSON_RETURN_WARNING = "Cannot return to form view: settings JSON is invalid."
UNDEFINED_BUTTON_ACTION_ERROR = "ACTION NOT DEFINED BUTTON {label} DOES NOTHING"
