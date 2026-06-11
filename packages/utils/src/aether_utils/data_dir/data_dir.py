from pathlib import Path
from platformdirs import user_data_dir
from .constants import AUTHORNAME


def get_base_dir(appname: str) -> Path:
    return Path(user_data_dir(appname=appname, appauthor=AUTHORNAME))


def _mkdir_if_not_exists(path: Path) -> None:
    """Create the directory if it does not exist."""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)


def get_data_dir(appname: str, subdir: Path | None = None) -> Path:
    """Get the path to the AETHER data directory."""
    base_dir = get_base_dir(appname)
    _mkdir_if_not_exists(base_dir)

    if subdir is None:
        return base_dir

    _mkdir_if_not_exists(base_dir / subdir)
    return base_dir / subdir
