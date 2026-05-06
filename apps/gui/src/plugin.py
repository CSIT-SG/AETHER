import sys
from pathlib import Path


def _add_workspace_package_paths() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    packages_dir = repo_root / "packages"
    if not packages_dir.is_dir():
        return

    for package_src in packages_dir.glob("*/src"):
        if not package_src.is_dir():
            continue
        package_src_path = str(package_src)
        if package_src_path not in sys.path:
            sys.path.insert(0, package_src_path)


_add_workspace_package_paths()

import idaapi
from aether_utils.logger import get_logger


class _Aether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = wanted_name = "Aether"
    help = wanted_hotkey = ""

    def init(self) -> None:
        self._logger = get_logger("ida_plugin")
        self._logger.info("IDA plugin initialized")

    def run(self, arg) -> None:
        pass


def PLUGIN_ENTRY() -> _Aether:
    return _Aether()
