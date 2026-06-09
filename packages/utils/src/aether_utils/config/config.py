"""
AETHER config handling
"""

from __future__ import annotations

import json
from pathlib import Path

from aether_utils.find_root import find_repo_root
from aether_utils.logger import get_logger
from pydantic import ValidationError
from .models import AetherConfig


def get_config_file_path() -> Path:
    repo_root: Path = find_repo_root()
    gui_src = repo_root / "apps" / "gui" / "src"
    gui_src.mkdir(parents=True, exist_ok=True)

    filename = "aether-next-config.json"
    return gui_src / filename


CONFIG_FILE = get_config_file_path()

# Logger for this module
logger = get_logger("config")


def _write_config_file(config: AetherConfig, file_path: Path) -> bool:
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(config.model_dump(), f, indent=2)
        return True
    except Exception as e:
        logger.error("Error saving config file: %s", e)
        return False


def load_config(config_file_path: Path = CONFIG_FILE) -> AetherConfig:
    try:
        with open(config_file_path, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        logger.info("Config file not found or unreadable at %s, using defaults", config_file_path)
        raw = {}

    try:
        cfg = AetherConfig.model_validate(raw)
    except ValidationError as e:
        raise ValueError(f"Config validation error: {e}") from e

    try:
        _write_config_file(cfg, config_file_path)
    except Exception as e:
        logger.error("Error writing default config file: %s", e)
    return cfg
