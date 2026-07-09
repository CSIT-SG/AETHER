import argparse
import contextlib
import multiprocessing as mp
from multiprocessing import connection

from aether_utils.config import get_config, get_config_file_path
from aether_utils.logger import get_logger

from .runners import mcp_runner, rpc_runner

logger = get_logger("AETHER CLI")


def _shutdown(proc: mp.Process, timeout: float = 10.0) -> None:
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()


def aether_cli() -> None:
    parser = argparse.ArgumentParser(prog="AETHER_CLI", description="Run AETHER CLI on an idb")
    parser.add_argument("--idb", required=True)
    parser.add_argument("--ida-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind on (default: 127.0.0.1)")

    args = parser.parse_args()

    logger.info(f"Config: {get_config()}")
    logger.info(f"Config file can be found at {get_config_file_path()}")

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

    with contextlib.suppress(KeyboardInterrupt):
        connection.wait([rpc_proc.sentinel, mcp_proc.sentinel])

    _shutdown(rpc_proc)
    _shutdown(mcp_proc)
