import sys
from pathlib import Path

# We can't import the find_repo_root function from aether_utils because it relies on workspace imports, which wont work until we add the necessary paths to sys.path.
# Instead, we re-implement the logic here to find the repo root and add the necessary paths to sys.path.

def _find_repo_root(start: Path | None = None) -> Path:
    """Find repo root by walking up from start"""
    start = start.resolve() if start else Path(__file__).resolve()

    markers = ["VERSION", "packages"]
    current = start if start.is_dir() else start.parent

    while current != current.parent:
        if any((current / marker).exists() for marker in markers):
            return current
        current = current.parent

    raise FileNotFoundError(f"Repo root not found from {start} (looked for {markers})")


def _add_workspace_package_paths() -> None:
    """Add paths to all workspace packages' src directories to sys.path."""
    repo_root = _find_repo_root()

    gui_src_dir = Path(__file__).resolve().parent
    if (gui_src_path := str(gui_src_dir)) not in sys.path:
        sys.path.insert(0, gui_src_path)

    packages_dir = repo_root / "packages"
    if not packages_dir.is_dir():
        return

    for package_src in packages_dir.glob("*/src"):
        if package_src.is_dir() and (p := str(package_src)) not in sys.path:
            sys.path.insert(0, p)


_add_workspace_package_paths()

import idaapi  # noqa: E402
from aether_gui import main as aether_gui_main  # noqa: E402
from aether_utils.logger import get_logger  # noqa: E402


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""

    def init(self) -> None:
        self._logger = get_logger("ida_plugin")
        self._logger.info("IDA plugin initialized")
        aether_gui_main()

    def run(self, arg) -> None:
        pass


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()
