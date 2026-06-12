from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import rpyc


@asynccontextmanager
async def get_rpc_connection(port: int) -> AsyncGenerator[Any, None]:
    """Establish an RPyC connection to the IDA RPC server."""
    conn = rpyc.connect(
        "127.0.0.1",
        port,
        config={
            "allow_public_attrs": True,
            "allow_pickle": True,
        },
    )
    try:
        yield conn.root
    finally:
        conn.close()
