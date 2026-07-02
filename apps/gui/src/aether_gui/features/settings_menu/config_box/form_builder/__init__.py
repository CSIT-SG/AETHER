"""VSCode-style, categorized settings form built from a pydantic model.

:func:`build_settings_form` walks ``model_cls.model_fields`` and groups them into
categories: top-level scalar fields land in a "General" section, while each nested
``BaseModel`` field becomes its own titled section. It returns a :class:`SettingsForm`
bundling the container widget, a getter that collects the live values into a nested
``dict``, the ordered sections (for the navigation sidebar), and the searchable leaf
rows (for live filtering).
"""

from .builder import build_settings_form
from .types import SettingsForm

__all__ = ["SettingsForm", "build_settings_form"]
