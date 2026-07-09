import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
import rpyc

HEADLESS_PORT = 57001
ENTRYPOINT = Path(__file__).parent.parent.parent / "scripts" / "run_headless.py"


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


@pytest.fixture(scope="package")
def BIN_NAME() -> str:
    return "basic"


@pytest.fixture(scope="package")
def ida_dir() -> str:
    d = os.environ.get("IDADIR", "")
    if not d:
        pytest.skip("IDADIR not set")
    return d


@pytest.fixture(scope="package")
def headless_ida(
    get_binary: Callable[..., Path], ida_dir: str, BIN_NAME
) -> Generator[tuple[str, int], None, None]:
    if not _port_is_free(HEADLESS_PORT):
        pytest.skip(f"Port {HEADLESS_PORT} is already in use")

    bin_path = get_binary(BIN_NAME)

    # remove the idb file
    # find all files with the same stem as bin_path and suffix .idb or .i64, and delete them
    with contextlib.suppress(Exception):
        for p in bin_path.parent.glob(f"{bin_path.stem}.*"):
            if p.suffix in [".idb", ".i64"]:
                p.unlink()

    proc = subprocess.Popen(
        [
            sys.executable,
            str(ENTRYPOINT),
            str(bin_path),
            "--ida-dir",
            ida_dir,
            "--host",
            "127.0.0.1",
            "--port",
            str(HEADLESS_PORT),
        ],
        env={**os.environ, "IDADIR": ida_dir},
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )

    # Wait for the port to start accepting connections
    deadline = time.monotonic() + 10
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

    if sys.platform == "win32":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.send_signal(signal.SIGTERM)

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="package")
def ida_client(headless_ida: tuple[str, int]) -> Generator[rpyc.Connection, None, None]:
    host, port = headless_ida
    conn = rpyc.connect(host, port, config={"allow_public_attrs": True})
    yield conn
    conn.close()


@pytest.fixture(scope="package")
def test_connection_is_alive(ida_client: rpyc.Connection) -> None:
    assert ida_client.root is not None
