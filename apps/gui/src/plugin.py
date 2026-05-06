import sys
from pathlib import Path
from aether_utils.find_root import find_repo_root  # or wherever you put it

def _add_workspace_package_paths() -> None:
    repo_root = find_repo_root(Path(__file__))

    gui_src_dir = Path(__file__).resolve().parent
    if (gui_src_path := str(gui_src_dir)) not in sys.path:
        sys.path.insert(0, gui_src_path)

    packages_dir = repo_root / "packages"
    if not packages_dir.is_dir():
        return

    for package_src in packages_dir.glob("*/src"):
        if package_src.is_dir():
            if (p := str(package_src)) not in sys.path:
                sys.path.insert(0, p)

_add_workspace_package_paths()

import idaapi
from aether_utils.logger import get_logger
from aether_gui import main as aether_gui_main

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
