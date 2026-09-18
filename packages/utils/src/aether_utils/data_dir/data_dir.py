from pathlib import Path

from platformdirs import user_data_dir

from .constants import AUTHORNAME, AppName


def _get_base_dir(appname: AppName) -> Path:
    # platformdirs ignores appauthor on Unix, so passing it there would put apps
    # straight into ~/.local/share (e.g. ~/.local/share/gui). Carry the author in
    # appname instead; Windows resolves to the same path it always has.
    return Path(user_data_dir(appname=AUTHORNAME, appauthor=False)) / appname


def _mkdir_if_not_exists(path: Path) -> None:
    """Create the directory if it does not exist."""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)


def get_data_dir(appname: AppName, subdir: Path | None = None) -> Path:
    """Get the path to the AETHER data directory."""
    base_dir = _get_base_dir(appname)
    _mkdir_if_not_exists(base_dir)

    if subdir is None:
        return base_dir

    _mkdir_if_not_exists(base_dir / subdir)
    return base_dir / subdir
