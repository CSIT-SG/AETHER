from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import aether_utils.config
import pytest


@pytest.fixture
def mock_config_file(tmp_path: Path) -> Generator[Path, None, None]:
    """Redirects CONFIG_FILE to a temp path for the duration of each test."""
    fake_path: Path = tmp_path / "aether-next-config.json"
    with patch.object(aether_utils.config, "CONFIG_FILE", fake_path):
        yield fake_path
