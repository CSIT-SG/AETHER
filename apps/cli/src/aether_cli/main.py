import argparse
import threading

from .runners import mcp_runner, rpc_runner


def aether_cli() -> None:
    parser = argparse.ArgumentParser(prog="AETHER_CLI", description="Run AETHER CLI on an idb")
    parser.add_argument("--idb", required=True)
    parser.add_argument("--ida-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind on (default: 127.0.0.1)")

    args = parser.parse_args()
    mcp_thread = threading.Thread(
        target=mcp_runner,
        args=(args.host,),
        daemon=True,
        name="mcp-server",
    )
    mcp_thread.start()

    try:
        rpc_runner(args.idb, args.ida_dir, args.host)
    finally:
        mcp_thread.join(timeout=5)
