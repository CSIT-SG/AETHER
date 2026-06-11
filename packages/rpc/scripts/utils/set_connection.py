from typing import Any

import rpyc


def set_connection(host: str, port: int) -> Any:
    """Establish an RPyC connection to the IDA RPC server."""
    try:
        conn = rpyc.connect(
            host,
            port,
            config={
                "allow_public_attrs": True,
                "allow_pickle": True,
            },
        )
        return conn
    except Exception as exc:
        raise ConnectionError(f"Failed to connect to RPC server at {host}:{port}: {exc}") from exc
