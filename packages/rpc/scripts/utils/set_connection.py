import rpyc
import sys


def set_connection(host: str, port: int) -> rpyc.Connection:
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
        print(f"RPC call failed: {exc}", file=sys.stderr)
        sys.exit(1)