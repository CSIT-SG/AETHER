import contextlib

from commitizen.config import read_cfg
from commitizen.exceptions import CommitizenException
from commitizen.providers import get_provider

from aether_utils.find_root import find_repo_root


def get_version() -> str:
    """
    Get the version of the repo using the commitizen SDK's configured version provider.
    """
    try:
        repo_root = find_repo_root()
        with contextlib.chdir(repo_root):
            provider = get_provider(read_cfg())
            return provider.get_version()
    except (FileNotFoundError, KeyError, CommitizenException):
        return "unknown"
