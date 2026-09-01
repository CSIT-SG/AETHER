import tomllib
from typing import cast

from aether_utils.find_root import find_repo_root


def get_version() -> str:
    """
    Get the version of the repo by reading the root pyproject.toml.
    """
    try:
        repo_root = find_repo_root()
        pyproject_file = repo_root / "pyproject.toml"
        if pyproject_file.exists():
            data = tomllib.loads(pyproject_file.read_text())
            assert "project" in data and "version" in data["project"]
            return cast(str, data["project"]["version"])
    except (FileNotFoundError, KeyError, AssertionError):
        pass
    return "unknown"
