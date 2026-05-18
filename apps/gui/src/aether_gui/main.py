import json

from aether_core.config import load_config
from aether_utils.logger import get_logger


def main() -> None:
    logger = get_logger("gui")
    cfg = load_config()
    logger.info("Config loaded: %s", json.dumps(cfg.model_dump(), indent=2))
