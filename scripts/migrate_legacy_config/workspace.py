import sys
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.parent
UTILS_SRC_DIR = ROOT_DIR / "packages" / "utils" / "src"


def ensure_utils_src_on_path() -> None:
    """Put ``packages/utils/src`` on ``sys.path`` so ``aether_utils`` imports
    resolve even when this package is run directly (not via ``uv run``)."""
    utils_src = str(UTILS_SRC_DIR)
    if utils_src not in sys.path:
        sys.path.insert(0, utils_src)
