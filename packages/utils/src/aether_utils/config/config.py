import json
from pathlib import Path
from typing import Any

from aether_utils.data_dir import get_data_dir
from aether_utils.logger import get_logger

from .constants import DEFAULT_CONFIG
from .models import ConfigModel


def get_config_file_path() -> Path:
    base = get_data_dir("_global")
    filename = "config.json"
    return base / filename


class ConfigManager:
    def __init__(self) -> None:
        self.logger = get_logger("config")
        self.config_file = get_config_file_path()
        self._config = self.load_config()

    @property
    def config(self) -> ConfigModel:
        return self._config

    @config.setter
    def config(self, config: ConfigModel) -> None:
        self._write_config_file(config)
        self._config = config

    def _write_config_file(self, config: ConfigModel) -> bool:
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config.model_dump(), f, indent=2)
            return True
        except Exception as e:
            self.logger.error("Error saving config file: %s", e)
            return False

    def load_config(self) -> ConfigModel:
        if not self.config_file.is_file():
            self.logger.info(
                "Config file not found or unreadable at %s, using defaults", self.config_file
            )
            cfg = DEFAULT_CONFIG
        else:
            print("Loading config from %s", self.config_file)
            with open(self.config_file, encoding="utf-8") as f:
                raw = json.load(f)

            cfg = self.validate_config(raw)

        self.config = cfg
        return cfg

    @staticmethod
    def validate_config(raw: dict[str, Any]) -> ConfigModel:
        return ConfigModel.model_validate(raw)
