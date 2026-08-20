import importlib
import threading
from pathlib import Path
from typing import Any

import rpyc

from aether_benchmark.utils.task import Task
from aether_rpc.capabilities import EXPORTS as caps_exports
from aether_rpc.executors.headless_executor import HeadlessExecutor
from aether_rpc.server import RPCServer

class StartRPCServerTask(Task[[Path, str], Any]): 
    """Start a headless IDA RPC server for the given IDB.

    Opens the IDB in headless mode via ``HeadlessExecutor``, starts an RPyC
    server exposing all capabilities, and returns the RPC service root
    that agent tools can call methods on.

    Cleanup (server stop, connection close) happens in ``cancel()``.
    """

    def __init__(self) -> None:
        self._server: Any = None
        self._conn: rpyc.Connection | None = None
        self._pump_thread: threading.Thread | None = None

    async def start(self, ida_dir: Path, idb_path: str) -> Any: 
        capabilities = [
            getattr(importlib.import_module(mod_path, "aether_rpc.capabilities"), name)()
            for name, mod_path in caps_exports.items()
        ]
        executor = HeadlessExecutor(idb_path, str(ida_dir))
        rpc_id = f"benchmark_{Path(idb_path).stem}"

        self._server = RPCServer(rpc_id, executor, capabilities)
        self._server.start() 

        self._pump_thread = threading.Thread(
            target=executor.pump,
            daemon=True,
            name=f"pump-{rpc_id}",
        )
        self._pump_thread.start()

        self._conn = rpyc.connect("127.0.0.1", self._server.port)
        return self._conn.root

    async def cancel(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:
                pass
