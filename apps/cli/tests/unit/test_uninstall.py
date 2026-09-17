from __future__ import annotations

from pathlib import Path

import pytest
import uninstall as cli
from platformdirs import user_data_dir


@pytest.fixture
def rmtree_target(monkeypatch: pytest.MonkeyPatch) -> Path:
    """The directory remove_data_dirs would delete, with the deletion stubbed out."""
    captured: list[Path] = []
    monkeypatch.setattr(cli.shutil, "rmtree", lambda path: captured.append(Path(path)))

    cli.remove_data_dirs()

    return captured[0]


def test_removes_only_the_app_data_dir(rmtree_target: Path) -> None:
    """`user_data_dir` silently ignores the author when `appname` is omitted and returns
    the bare base directory (`%LOCALAPPDATA%` on Windows).
    """
    assert cli.APP_AUTHOR in str(rmtree_target)
    assert Path(user_data_dir()) in rmtree_target.parents
