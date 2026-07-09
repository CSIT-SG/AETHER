import argparse
import multiprocessing as mp
import time

from .runners import mcp_runner, rpc_runner


def aether_cli() -> None:
    parser = argparse.ArgumentParser(prog="AETHER_CLI", description="Run AETHER CLI on an idb")
    parser.add_argument("--idb", required=True)
    parser.add_argument("--ida-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind on (default: 127.0.0.1)")

    args = parser.parse_args()
    mp.set_start_method("spawn", force=True)

    rpc_proc = mp.Process(
        target=rpc_runner,
        args=(args.idb, args.ida_dir, args.host),
        name="rpc-server",
    )
    rpc_proc.start()

    mcp_proc = mp.Process(
        target=mcp_runner,
        args=(args.host,),
        name="mcp-server",
    )
    mcp_proc.start()

    try:
        while rpc_proc.is_alive() and mcp_proc.is_alive():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass

    rpc_proc.join()
    mcp_proc.join()
