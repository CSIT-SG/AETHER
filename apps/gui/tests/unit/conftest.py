import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.utils.linker import LINKS

DEFAULT_INSTALLER_IGNORE = [
    ".gitignore",
    "CONTRIBUTING.md",
    ".git",
    "pyrightconfig.json",
    "uv.lock",
]


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


# conftest.py — build src_dir from LINKS instead of hardcoding
@pytest.fixture
def src_dir(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    for src_name in LINKS:
        full_path = src / src_name
        full_path.parent.mkdir(parents=True, exist_ok=True)
        suffix = Path(src_name).suffix
        full_path.write_text("# generated" if suffix == ".py" else "{}")
    return src


@pytest.fixture
def dst_dir(tmp_path: Path) -> Path:
    dst = tmp_path / "dst"
    dst.mkdir()
    return dst


@pytest.fixture
def symlink_supported(tmp_path: Path) -> bool:
    probe_target = tmp_path / "_probe_target"
    probe_link = tmp_path / "_probe_link"
    probe_target.write_text("")
    try:
        probe_link.symlink_to(probe_target)
        probe_link.unlink()
        return True
    except (OSError, NotImplementedError):
        return False
