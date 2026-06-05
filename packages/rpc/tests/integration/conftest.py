import os
import threading
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
import rpyc
from entrypoint_headless import main


@pytest.fixture(scope="session")
def ida_dir() -> str:
    d = os.environ.get("IDADIR", "")
    if not d:
        pytest.skip("IDADIR not set")
    return d


BIN_NAME = "basic"


@pytest.fixture(scope="session")
def headless_ida(
    get_binary: Callable[[str], Path], ida_dir: str
) -> Generator[tuple[str, int], None, None]:
    idb_path = get_binary(BIN_NAME)

    ready = threading.Event()
    stop = threading.Event()
    host_port: tuple[str, int] = ("", 0)
    exc: BaseException | None = None

    def _on_ready(host: str, port: int) -> None:
        nonlocal host_port
        host_port = (host, port)
        ready.set()

    def _run() -> None:
        nonlocal exc
        try:
            main(str(idb_path), ida_dir, on_ready=_on_ready, stop_event=stop)
        except BaseException as e:
            exc = e
            ready.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    if not ready.wait(timeout=60):
        pytest.fail("Headless IDA server did not become ready within 60s")

    if exc is not None:
        raise exc

    yield host_port

    stop.set()  # clean shutdown
    t.join(timeout=10)


@pytest.fixture(scope="session")
def ida_client(headless_ida: tuple[str, int]) -> Generator[rpyc.Connection, None, None]:
    host, port = headless_ida
    conn = rpyc.connect(host, port, config={"allow_public_attrs": True})
    yield conn
    conn.close()
