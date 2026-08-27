from __future__ import annotations

import asyncio
import contextlib
import importlib
import threading
from pathlib import Path
from threading import Event

import aether_rpc.capabilities as caps
import rpyc
from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.executors.headless_executor import HeadlessExecutor
from aether_rpc.server import RPCServer
from aether_utils.file_id import file_id
from aether_utils.get_port import get_port
from aether_utils.logger import get_logger

from aether_benchmark.utils.task import Task

logger = get_logger("AETHER_BENCHMARK.RPC")


class StartRPCServerTask(Task[[Path, str], AnyService]):
    """Start an in-process headless IDA RPC server for the given IDB."""

    def __init__(self) -> None:
        self._conn: rpyc.Connection | None = None
        self._server: RPCServer | None = None
        self._pump_thread: threading.Thread | None = None
        self._ready = Event()
        self._startup_error: BaseException | None = None

    async def start(self, ida_dir: Path, idb_path: str) -> AnyService:
        host = "127.0.0.1"
        port = get_port(host)

        logger.debug("Setting executor & capabilities")
        executor = HeadlessExecutor(idb_path, str(ida_dir))
        capabilities = [
            getattr(importlib.import_module(module_path, caps.__name__), name)()
            for name, module_path in caps.EXPORTS.items()
        ]

        logger.debug("Creating RPC Server")
        server = RPCServer(file_id(idb_path), executor, capabilities, host=host, port=port)
        self._server = server

        def _serve() -> None:
            logger.debug("Starting RPC Server")
            server.start()  # Keep IDA startup and pumping on one thread.
            self._ready.set()

            if self._startup_error is not None:
                return

            logger.debug("Before pump()")
            try:
                executor.pump()
            except BaseException as exc:
                self._startup_error = exc
                logger.exception("RPC executor stopped unexpectedly")
            logger.debug("After pump()")

        logger.debug("Server thread starting.")
        self._pump_thread = threading.Thread(
            target=_serve,
            name="aether-rpc-executor",
            daemon=True,
        )
        self._pump_thread.start()

        logger.debug("Awaiting for thread")
        await asyncio.to_thread(self._ready.wait)
        logger.debug("After await")
        if self._startup_error is not None:
            await self.cancel()
            raise RuntimeError("Failed to start the RPC server") from self._startup_error

        logger.debug("Connecting to RPyC")
        try:
            conn = await asyncio.to_thread(rpyc.connect, host, port)
        except BaseException:
            logger.debug("Exception with connection")
            await self.cancel()
            raise

        self._conn = conn
        return conn.root

    async def cancel(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None

        if self._server is not None:
            self._server.stop()
            self._server = None

        if self._pump_thread is not None:
            await asyncio.to_thread(self._pump_thread.join)
            self._pump_thread = None
