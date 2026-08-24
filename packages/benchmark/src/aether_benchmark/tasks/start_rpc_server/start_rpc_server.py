from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import rpyc
from aether_utils.find_root import find_repo_root

from aether_benchmark.utils.task import Task

_HEADLESS_ENTRYPOINT = find_repo_root() / "packages" / "rpc" / "scripts" / "run_headless.py"
_READY_TIMEOUT = 30.0


def _free_port() -> int:
    """Ask the OS for an available TCP port on the loopback interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _port_accepting(port: int) -> bool:
    """Return True if something is accepting connections on ``port``."""
    with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        return True
    return False


class StartRPCServerTask(Task[[Path, str], Any]):
    """Start a headless IDA RPC server for the given IDB.

    Launches ``run_headless.py`` as a subprocess (IDA's API is main-thread
    only, so the server cannot share the benchmark's asyncio main thread),
    waits for it to start listening, connects an RPyC client, and returns the
    service root that agent tools can call methods on.

    Cleanup (terminating the subprocess and closing the connection) happens in
    ``cancel()``.
    """

    def __init__(self) -> None:
        self._conn: rpyc.Connection | None = None
        self._proc: subprocess.Popen[str] | None = None

    async def start(self, ida_dir: Path, idb_path: str) -> Any:
        port = _free_port()
        proc = self._launch_headless(port, ida_dir, idb_path)
        self._proc = proc

        # Wait for the port to accept connections, or the process to die.
        deadline = time.monotonic() + _READY_TIMEOUT
        while not _port_accepting(port):
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(
                    f"Headless IDA server exited with code {proc.returncode}: {stderr}"
                )
            if time.monotonic() > deadline:
                self._terminate(proc)
                raise TimeoutError(
                    f"Headless IDA server did not become ready within {_READY_TIMEOUT}s"
                )
            await asyncio.sleep(0.2)

        conn = rpyc.connect("127.0.0.1", port)
        self._conn = conn
        return conn.root

    async def cancel(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None
        if self._proc is not None:
            self._terminate(self._proc)
            self._proc = None

    @staticmethod
    def _launch_headless(
        port: int,
        ida_dir: Path,
        idb_path: str,
    ) -> subprocess.Popen[str]:
        """Spawn ``run_headless.py`` bound to the given port and directory."""
        return subprocess.Popen(
            [
                sys.executable,
                str(_HEADLESS_ENTRYPOINT),
                idb_path,
                "--ida-dir",
                str(ida_dir),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            env={**os.environ, "IDADIR": str(ida_dir)},
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0),
            stderr=subprocess.PIPE,
            text=True,
        )

    @staticmethod
    def _terminate(proc: subprocess.Popen[str]) -> None:
        """Stop the subprocess, escalating to kill if it does not exit."""
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
