import asyncio
import os
import signal
import sys
from pathlib import Path

import aether_rpc.capabilities as caps
from aether_rpc import RPCServer
from aether_rpc.executors.headless_executor import HeadlessExecutor, configure_idapro
from aether_utils.logger import get_logger

logger = get_logger("headless_ida")


async def main(
    idb_path: str,
    ida_install_dir: str,
    host: str = "127.0.0.1",
    port: int = 0,  # 0 = OS picks a free port
) -> None:
    configure_idapro(ida_install_dir)

    executor = HeadlessExecutor(idb_path, ida_install_dir)
    capabilities = [getattr(caps, c)() for c in caps.__all__]

    server = RPCServer(executor, capabilities, host=host, port=port)

    await executor.startup()
    server.start()

    # Print the port so the test harness can read it from stdout
    print(f"HEADLESS_IDA_PORT={server.port}", flush=True)
    logger.info(f"Headless IDA RPC server started on port {server.port}")

    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    await stop_event.wait()

    logger.info("Shutting down...")
    server.stop()
    await executor.shutdown()
    logger.info("Shutdown complete")


def cli() -> None:
    """Entrypoint for uv run / direct invocation."""
    import argparse

    parser = argparse.ArgumentParser(description="Headless IDA RPC server")
    parser.add_argument("idb_path", help="Path to the .idb / .i64 database")
    parser.add_argument(
        "--ida-dir",
        default=os.environ.get("IDADIR", ""),
        help="IDA installation directory (or set IDADIR env var)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    if not args.ida_dir:
        print("ERROR: --ida-dir or IDADIR env var required", file=sys.stderr)
        sys.exit(1)

    if not Path(args.idb_path).exists():
        print(f"ERROR: idb not found: {args.idb_path}", file=sys.stderr)
        sys.exit(1)

    asyncio.run(main(args.idb_path, args.ida_dir, args.host, args.port))


if __name__ == "__main__":
    cli()
