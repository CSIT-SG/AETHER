from pathlib import Path
from platformdirs import user_data_dir
from .constants import APP_NAME

base_dir = Path(user_data_dir(APP_NAME))

def _mkdir_if_not_exists(path: Path) -> None:
    """Create the directory if it does not exist."""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)

def get_data_dir(subdir: Path | None = None) -> Path:
    """Get the path to the AETHER data directory."""
    if subdir is None:
        return base_dir

    _mkdir_if_not_exists(base_dir / subdir)
    return base_dir / subdir