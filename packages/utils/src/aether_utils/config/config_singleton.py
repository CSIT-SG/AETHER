from typing import Any

from .config import ConfigManager
from .models import ConfigModel

_config_manager: ConfigManager | None = None


def get_config() -> ConfigModel:
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.config


def set_config(raw: dict[str, Any]) -> None:
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    _config_manager.config = raw
