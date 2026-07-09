import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aether_utils.data_dir import get_data_dir
from aether_utils.logger import get_logger

from .constants import DEFAULT_CONFIG
from .models import ConfigModel


@dataclass(frozen=True)
class ConfigFileState:
    modified_ns: int
    size: int
    file_id: int


def get_config_file_path() -> Path:
    base = get_data_dir("_global")
    filename = "config.json"
    return base / filename


class ConfigManager:
    def __init__(self) -> None:
        self.logger = get_logger("config")
        self.config_file = get_config_file_path()
        self._config_file_state: ConfigFileState | None = None
        self._config = self.load_config()

    @property
    def config(self) -> ConfigModel:
        if self._config_file_state != self._current_config_file_state():
            self._config = self.load_config()
        return self._config

    @config.setter
    def config(self, raw: dict[str, Any]) -> None:
        cfg = self.validate_config(raw)
        self._write_config_file(cfg)
        self._config = cfg
        self._config_file_state = self._current_config_file_state()

    def _write_config_file(self, config: ConfigModel) -> None:
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config.model_dump(), f, indent=2)
        except OSError as e:
            self.logger.error("Error saving config file: %s", e)
            raise

    def load_config(self) -> ConfigModel:
        if not self.config_file.is_file():
            self.logger.info(
                "Config file not found or unreadable at %s, using defaults", self.config_file
            )
            cfg = DEFAULT_CONFIG
            try:
                self.config = cfg.model_dump()  # type: ignore
            except OSError:
                # First-run persist failed (e.g. read-only dir); keep going with
                # in-memory defaults rather than blocking startup.
                self.logger.warning("Could not persist default config; using in-memory defaults.")
        else:
            self.logger.info("Loading config from %s", self.config_file)
            try:
                with open(self.config_file, encoding="utf-8") as f:
                    raw = json.load(f)
                cfg = self.validate_config(raw)
                self._config_file_state = self._current_config_file_state()
            except Exception as e:
                self.logger.warning("Config JSON erroneously modified on disk.")
                raise e
        return cfg

    def _current_config_file_state(self) -> ConfigFileState | None:
        if not self.config_file.is_file():
            return None

        try:
            stat = self.config_file.stat()
        except FileNotFoundError:
            return None
        return ConfigFileState(stat.st_mtime_ns, stat.st_size, stat.st_ino)

    @staticmethod
    def validate_config(raw: dict[str, Any]) -> ConfigModel:
        return ConfigModel.model_validate(raw)
