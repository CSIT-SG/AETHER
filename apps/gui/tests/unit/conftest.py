import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


DEFAULT_INSTALLER_IGNORE = [
    ".gitignore",
    "CONTRIBUTING.md",
    ".git",
    "pyrightconfig.json",
    "uv.lock",
]


def _can_create_symlink() -> bool:
    if not hasattr(os, "symlink"):
        return False
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            src = Path(tmp_dir) / "src.txt"
            dst = Path(tmp_dir) / "dst.txt"
            src.write_text("x")
            os.symlink(src, dst)
            return dst.is_symlink()
    except OSError:
        return False


@pytest.fixture(scope="session")
def symlink_supported() -> bool:
    return _can_create_symlink()


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    """
    A fake project root containing a minimal .gitignore and a handful of
    files/directories that installer.main() can operate on.

    Layout:
        <tmp_root>/
            .gitignore          <- contains one pattern: "ignored_dir"
            main.py
            README.md
            ignored_dir/
                secret.py
            allowed_dir/
                helper.py
    """
    root = tmp_path / "project"
    root.mkdir()

    (root / ".gitignore").write_text("ignored_dir\n")
    (root / "main.py").write_text("# main")
    (root / "README.md").write_text("# readme")

    ignored = root / "ignored_dir"
    ignored.mkdir()
    (ignored / "secret.py").write_text("# secret")

    allowed = root / "allowed_dir"
    allowed.mkdir()
    (allowed / "helper.py").write_text("# helper")

    return root


@pytest.fixture
def plugin_dir(tmp_path: Path) -> Path:
    """Empty directory that acts as the IDA plugins destination."""
    dest = tmp_path / "plugins"
    dest.mkdir()
    return dest


@pytest.fixture
def src_dir(tmp_path: Path) -> Path:
    """
    Source directory for linker tests containing the files that get symlinked.

        <src_dir>/
            plugin.py
            gui_plugin.py
            aether-next-config.json
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "plugin.py").write_text("# plugin")
    (src / "gui_plugin.py").write_text("# gui plugin")
    (src / "aether-next-config.json").write_text("{}")
    return src


@pytest.fixture
def dst_dir(tmp_path: Path) -> Path:
    """Empty directory that acts as the symlink destination for linker tests."""
    dst = tmp_path / "dst"
    dst.mkdir()
    return dst
