import os
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
import rpyc

BIN_NAME = "basic"
HEADLESS_PORT = 57000


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


@pytest.fixture(scope="session")
def ida_dir() -> str:
    d = os.environ.get("IDADIR", "")
    if not d:
        pytest.skip("IDADIR not set")
    return d


@pytest.fixture(scope="session")
def headless_ida(
    get_binary: Callable[..., Path], ida_dir: str
) -> Generator[tuple[str, int], None, None]:
    if not _port_is_free(HEADLESS_PORT):
        pytest.skip(f"Port {HEADLESS_PORT} is already in use")

    idb_path = get_binary(BIN_NAME)

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "entrypoint_headless",
            str(idb_path),
            "--ida-dir",
            ida_dir,
            "--host",
            "127.0.0.1",
            "--port",
            str(HEADLESS_PORT),
        ],
        env={**os.environ, "IDADIR": ida_dir},
    )

    # Wait for the port to start accepting connections
    deadline = time.monotonic() + 60
    while True:
        if proc.poll() is not None:
            pytest.fail(f"Headless IDA server exited with code {proc.returncode}")
        if time.monotonic() > deadline:
            proc.kill()
            pytest.fail("Headless IDA server did not become ready within 60s")
        try:
            with socket.create_connection(("127.0.0.1", HEADLESS_PORT), timeout=1):
                break  # port is accepting connections
        except OSError:
            time.sleep(0.2)

    yield "127.0.0.1", HEADLESS_PORT

    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="session")
def ida_client(headless_ida: tuple[str, int]) -> Generator[rpyc.Connection, None, None]:
    host, port = headless_ida
    conn = rpyc.connect(host, port, config={"allow_public_attrs": True})
    yield conn
    conn.close()
