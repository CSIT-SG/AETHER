import contextlib
import json
import threading
from os import getpid

from aether_utils.data_dir import get_data_dir
from rpyc.utils.server import ThreadedServer

from .capabilities.base import Capability
from .executors import IDAExecutor
from .ida_service import IDAService


class RPCServer:
    def __init__(
        self,
        id: str,
        executor: IDAExecutor,
        capabilities: list[Capability],
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self._executor = executor
        self._capabilities = capabilities
        self._host = host
        self._port = port

        self._id = id
        self._data_file = get_data_dir("rpc") / f"{self._id}.json"

        self._server: ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Server not started")

        return self._server.port

    # we register ourselves in the file system when we start, and deregister when we stop.
    def _register(self) -> None:

        data = {
            "id": str(self._id),
            "port": self._server.port if self._server else None,
            "pid": getpid(),
        }

        self._data_file.write_text(json.dumps(data))

    def _deregister(self) -> None:
        self._data_file.unlink(missing_ok=True)

    def start(self) -> None:
        self._executor.startup()

        service = IDAService(
            self._executor,
            self._capabilities,
        )

        self._server = ThreadedServer(
            service,
            hostname=self._host,
            port=self._port,
            protocol_config={
                "allow_public_attrs": True,
                "allow_pickle": True,
            },
        )

        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
        )

        self._thread.start()
        self._register()

    def _run(self):
        if not self._server:
            raise RuntimeError("Server not initialized")
        self._server.start()

    def stop(self) -> None:
        if not self._server:
            return

        with contextlib.suppress(Exception):
            self._server.close()

        if self._thread:
            self._thread.join(timeout=2)

        self._executor.shutdown()

        self._deregister()
