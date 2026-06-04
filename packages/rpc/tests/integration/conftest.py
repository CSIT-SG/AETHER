from collections.abc import Callable, Generator
from typing import Any

import pytest
import rpyc
from aether_rpc import RPCServer
from aether_rpc.capabilities.base import Capability
from aether_rpc.executors.base import IDAExecutor


class DirectExecutor(IDAExecutor):  # type: ignore[misc]
    async def execute(self, callback: Callable[..., Any], arguments: dict[str, Any]) -> Any:
        return await callback(**arguments)

    async def startup(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass


class EchoCapability(Capability):  # type: ignore[misc]
    @property
    def name(self) -> str:
        return "echo"

    async def execute(self, **kwargs: Any) -> Any:
        return {"echo": kwargs}


class FailingCapability(Capability):  # type: ignore[misc]
    @property
    def name(self) -> str:
        return "fail"

    async def execute(self, **kwargs: Any) -> Any:
        raise ValueError("intentional failure")


@pytest.fixture(scope="module")
def executor() -> DirectExecutor:
    return DirectExecutor()


@pytest.fixture(scope="module")
def server(executor: DirectExecutor) -> Generator[RPCServer, None, None]:
    capabilities: list[Capability] = [EchoCapability(), FailingCapability()]
    srv = RPCServer(executor, capabilities)
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def client(server: RPCServer) -> Generator[rpyc.Connection, None, None]:
    conn = rpyc.connect("127.0.0.1", server.port, config={"allow_public_attrs": True})
    yield conn
    conn.close()
