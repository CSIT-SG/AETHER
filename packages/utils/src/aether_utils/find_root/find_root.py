from pathlib import Path


def find_repo_root(start: Path | None = None, markers: list[str] | None = None) -> Path:
    """
    Walk up from `start` until a repo root marker is found.
    Returns the root as a Path object.
    """
    if start is None:
        start = Path(__file__).resolve()
    if markers is None:
        # Default markers to identify the repo root
        markers = [".git", "VERSION"]

    current = start if start.is_dir() else start.parent
    # we recursively check if any of the markers exist in the current directory, if not we move up one level until we reach the root
    while current != current.parent:
        if any((current / marker).exists() for marker in markers):
            return current
        current = current.parent

    raise FileNotFoundError(f"Repo root not found from {start} (looked for {markers})")
