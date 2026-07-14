import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import AsyncGenerator, Callable, Generator
from pathlib import Path

import pytest
import pytest_asyncio
from aether_utils.find_root import find_repo_root
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

BIN_NAME = "basic"
HEADLESS_PORT = 57000
MCP_PORT = 6766
ENTRYPOINT = Path(__file__).parent.parent.parent / "scripts" / "run_headless.py"
RPC_ENTRYPOINT = find_repo_root() / "packages" / "rpc" / "scripts" / "run_headless.py"


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


@pytest.fixture(scope="package")
def ida_dir() -> str:
    d = os.environ.get("IDADIR", "")
    if not d:
        pytest.skip("IDADIR not set")
    return d


@pytest.fixture(scope="package", autouse=True)
def headless_ida(
    get_binary: Callable[..., Path], ida_dir: str
) -> Generator[subprocess.Popen[str], None, None]:
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
            str(RPC_ENTRYPOINT),
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
        stderr=subprocess.PIPE,
        text=True,  # Crucial so we get strings instead of raw bytes
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

    yield proc

    if sys.platform == "win32":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.send_signal(signal.SIGTERM)

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest_asyncio.fixture(scope="package")
async def headless_mcp() -> AsyncGenerator[tuple[str, int], None]:
    host = "127.0.0.1"

    if not _port_is_free(MCP_PORT):
        pytest.skip(f"Port {MCP_PORT} is already in use by another service.")

    # Launch the uvicorn script you refactored earlier
    proc = subprocess.Popen(
        [
            sys.executable,
            str(ENTRYPOINT),
            "--port",
            str(MCP_PORT),
            "--no-reload",
        ],
        env=os.environ.copy(),
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )

    # Poll until the Uvicorn port starts accepting socket connections
    deadline = time.monotonic() + 10  # 10 second timeout limit
    while True:
        if proc.poll() is not None:
            pytest.fail(f"MCP server exited prematurely with code {proc.returncode}")
        if time.monotonic() > deadline:
            proc.kill()
            pytest.fail("MCP server did not become ready within 10 seconds")
        try:
            with socket.create_connection((host, MCP_PORT), timeout=1):
                break  # The server is alive and accepting connections
        except OSError:
            time.sleep(0.2)

    yield host, MCP_PORT

    if sys.platform == "win32":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.send_signal(signal.SIGTERM)

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest_asyncio.fixture(scope="package")
async def mcp_client(
    headless_mcp: tuple[str, int],
) -> AsyncGenerator[Client[StreamableHttpTransport], None]:
    host, port = headless_mcp
    sse_url = f"http://{host}:{port}/mcp"

    transport = StreamableHttpTransport(url=sse_url)
    async with Client(transport) as client:
        yield client
    await client.close()


@pytest_asyncio.fixture(scope="package")
async def test_mcp_connection_is_alive(mcp_client: Client[StreamableHttpTransport]) -> None:
    try:
        await mcp_client.ping()
    except Exception as e:
        pytest.skip(f"MCP server could not be reached: {e}")

@pytest.fixture(scope = "package")
async def instance_ids(tmp_path_factory: pytest.TempPathFactory) -> AsyncGenerator:
    """Provides a temporary directory for the entire test session."""
    yield tmp_path_factory.mktemp("ID_Dir")
