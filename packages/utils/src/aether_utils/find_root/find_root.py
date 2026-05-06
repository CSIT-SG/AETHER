from pathlib import Path

def find_repo_root(start: Path | None = None, markers: list[str] | None = None) -> Path:
    """
    Walk up from `start` until a repo root marker is found.
    Returns the root as a Path object.
    """
    if start is None:
        start = Path(__file__).resolve()
    if markers is None:
        markers = [".git", "VERSION", "pyproject.toml"]

    current = start if start.is_dir() else start.parent
    while current != current.parent:
        if any((current / marker).exists() for marker in markers):
            return current
        current = current.parent

    raise FileNotFoundError(f"Repo root not found from {start} (looked for {markers})")