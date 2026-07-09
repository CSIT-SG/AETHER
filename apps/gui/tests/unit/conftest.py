from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture(scope="package")
def symlink_supported() -> bool:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        source = tmp_path / "source.txt"
        source.write_text("x")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(source)
        except OSError:
            return False
        return link.is_symlink()
