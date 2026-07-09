from pathlib import Path

from .schema import LegacySource
from .workspace import ensure_utils_src_on_path

ensure_utils_src_on_path()

from aether_utils.config.config import get_config_file_path  # noqa: E402

CONFIG_FILENAME = "config.json"


def current_config_path() -> Path:
    """AETHER Next config path.

    Delegates to aether_utils so the migration destination always matches the
    path the running app reads and writes: a single source of truth rather than
    an independent platformdirs guess that could silently diverge.
    """
    return get_config_file_path()


def legacy_sources() -> tuple[LegacySource, ...]:
    # AETHER-IDA is the only legacy install AETHER Next migrates from. Its config
    # lives outside this repo, so the path is a direct lookup with no in-repo
    # source of truth.
    return (
        LegacySource(
            "AETHER-IDA", Path.home() / "AppData" / "Local" / "AETHER-IDA" / CONFIG_FILENAME
        ),
    )
