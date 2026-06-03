import json
import sys
import urllib.request
from pathlib import Path

import idaapi

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


import aether_rpc.capabilities as caps  # noqa: E402
from aether_rpc import RPCServer  # noqa: E402
from aether_rpc.executors.gui_executor import GUIExecutor  # noqa: E402
from aether_utils.logger import get_logger  # noqa: E402

# TODO: implement registration with mcp server
CONTROLLER_URL = "http://127.0.0.1:13337"
CAPABILITIES = [getattr(caps, c)() for c in caps.__all__]
logger = get_logger("rpc_plugin")


class RPCPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "MCP RPC bridge"
    help = ""
    wanted_name = "mcp_rpc"
    wanted_hotkey = ""

    def init(self) -> int:
        print("Initializing RPC plugin...")
        executor = GUIExecutor()
        self._server = RPCServer(executor, CAPABILITIES)
        self._server.start()
        # self._register(self._server.port)
        logger.info(f"RPC server started on port {self._server.port}")
        return idaapi.PLUGIN_KEEP

    def term(self) -> None:
        self._server.stop()
        # self._deregister(self._server.port)
        logger.info("RPC server stopped")

    def run(self, arg: int) -> None:
        pass

    def _register(self, port: int) -> None:
        """Register this plugin with the controller so it can route requests here. We send the port and capabilities we support."""
        raise NotImplementedError("Plugin registration not implemented yet")

    def _deregister(self, port: int) -> None:
        """Deregister this plugin from the controller."""
        raise NotImplementedError("Plugin deregistration not implemented yet")

    def _post(self, path: str, payload: dict) -> None:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{CONTROLLER_URL}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            logger.error(f"controller unreachable: {e}")


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return RPCPlugin()
