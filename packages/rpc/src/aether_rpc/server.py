import contextlib
import threading

from rpyc.utils.server import ThreadedServer

from .capabilities.base import Capability
from .executors import IDAExecutor
from .ida_service import IDAService


class RPCServer:
    def __init__(
        self,
        executor: IDAExecutor,
        capabilities: list[Capability],
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self._executor = executor
        self._capabilities = capabilities
        self._host = host
        self._port = port

        self._server: ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Server not started")

        return self._server.port

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

    def _run(self):
        if not self._server:
            raise RuntimeError("Server not initialized")
        self._server.start()

    def stop(self) -> None:
        if not self._server:
            return

        with contextlib.suppress(Exception):
            self._server.close()

        # 3. Join thread
        if self._thread:
            self._thread.join(timeout=2)

        self._executor.shutdown()
