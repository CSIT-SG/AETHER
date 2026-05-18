from aether_utils.find_root import find_repo_root


def get_version() -> str:
    """
    Get the version of the repo by reading the VERSION file at the root.
    """
    try:
        repo_root = find_repo_root()
        version_file = repo_root / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
    except FileNotFoundError:
        pass
    return "unknown"
