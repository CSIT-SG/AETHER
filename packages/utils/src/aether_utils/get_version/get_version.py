import contextlib
import inspect
import io
from pathlib import Path

from commitizen.config import read_cfg
from commitizen.exceptions import CommitizenException
from commitizen.providers import get_provider

from aether_utils.find_root import find_repo_root


def get_version() -> str:
    """
    Get the local package version, resolved relative to the caller's file.
    """
    try:
        caller_file = Path(inspect.stack()[1].filename)
        root = find_repo_root(start=caller_file, markers=["pyproject.toml"])
        with contextlib.chdir(root):
            # read_cfg may print warnings (e.g. multiple config files detected)
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                cfg = read_cfg()
            provider = get_provider(cfg)
            return provider.get_version()
    except (FileNotFoundError, KeyError, CommitizenException):
        return "unknown"
