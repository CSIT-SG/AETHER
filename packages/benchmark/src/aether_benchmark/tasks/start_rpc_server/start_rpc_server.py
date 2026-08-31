from __future__ import annotations

import asyncio
import contextlib
import importlib
import os
import signal
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from threading import Event

import aether_rpc.capabilities as caps
import rpyc
from aether_backend.utils.get_rpc_service import AnyService
from aether_benchmark.utils.task import Task
from aether_rpc.executors.headless_executor import HeadlessExecutor
from aether_rpc.server import RPCServer
from aether_utils.configure_ida import configure_ida
from aether_utils.file_id import file_id
from aether_utils.get_port import get_port
from aether_utils.logger import get_logger

logger = get_logger("AETHER_BENCHMARK.RPC")


def headless_main(idb_path: str, ida_dir: str, host: str, port: int) -> None:
    """Run the IDA-bound RPC server in the child process main thread."""

    configure_ida(ida_dir)
    executor = HeadlessExecutor(idb_path, ida_dir)
    capabilities = [
        getattr(importlib.import_module(module_path, caps.__name__), name)()
        for name, module_path in caps.EXPORTS.items()
    ]
    server = RPCServer(file_id(idb_path), executor, capabilities, host=host, port=port)
    server.start()
    logger.info("Headless IDA RPC server started on port %d", server.port)

    stop_event = Event()

    def _handle_signal(_sig: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, _handle_signal)

    def _watch() -> None:
        stop_event.wait()
        server.stop()

    threading.Thread(target=_watch, daemon=True).start()
    executor.pump()


class StartRPCServerTask(Task[[Path, str], AnyService]):
    """Start and supervise a headless IDA RPC server subprocess."""

    def __init__(self) -> None:
        self._conn: rpyc.Connection | None = None
        self._proc: subprocess.Popen[bytes] | None = None

    async def start(self, ida_dir: Path, idb_path: str) -> AnyService:
        host = "127.0.0.1"
        port = get_port(host)

        # Subprocessing is required as RPC and headless must be
        # In the same running thread AND that thread must be the main thread.
        # Hence, subprocess would spawn them in a new python process.
        command = [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import sys

                from aether_benchmark.tasks.start_rpc_server.start_rpc_server import headless_main

                headless_main(
                    sys.argv[1],
                    sys.argv[2],
                    sys.argv[3],
                    int(sys.argv[4]),
                )
                """
            ),
            str(idb_path),
            str(ida_dir),
            host,
            str(port),
        ]
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self._proc = subprocess.Popen(
            command,
            env=os.environ.copy(),
            creationflags=creationflags,
        )

        try:
            # Checks around 30 seconds before timeout
            for _ in range(300):
                if self._proc.poll() is not None:
                    raise RuntimeError("Headless RPC server exited during startup")
                try:
                    conn = await asyncio.to_thread(rpyc.connect, host, port)
                    break
                except OSError:
                    await asyncio.sleep(0.1)
            else:
                raise TimeoutError("Timed out waiting for headless RPC server")
        except BaseException:
            await self.cancel()
            raise

        self._conn = conn
        return conn.root

    async def cancel(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None

        if self._proc is not None:
            proc = self._proc
            if proc.poll() is not None:
                return

            with contextlib.suppress(Exception):
                if sys.platform == "win32":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            proc.terminate()
            self._proc = None
