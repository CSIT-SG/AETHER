import argparse
import signal
import sys
import threading
from collections.abc import Callable
from os import environ
from pathlib import Path
from threading import Event

from aether_rpc.executors.headless_executor import HeadlessExecutor, configure_idapro
from aether_utils.logger import get_logger

logger = get_logger("rpc_headless_plugin")


def main(
    idb_path: str,
    ida_install_dir: str,
    host: str = "127.0.0.1",
    port: int = 0,
    on_ready: Callable[[str, int], None] | None = None,
    stop_event: Event | None = None,
) -> None:
    configure_idapro(ida_install_dir)

    import aether_rpc.capabilities as caps
    from aether_rpc.server import RPCServer

    executor = HeadlessExecutor(idb_path, ida_install_dir)
    capabilities = [getattr(caps, c)() for c in caps.__all__]
    server = RPCServer(executor, capabilities, host=host, port=port)
    server.start()  # calls executor.startup() on this (main) thread

    logger.info(f"Headless IDA RPC server started on port {server.port}")

    if on_ready:
        on_ready(host, server.port)

    if stop_event is None:
        stop_event = Event()

    # Watch for shutdown signal on a background thread, then unblock pump()
    def _watch() -> None:
        stop_event.wait()
        logger.info("Shutting down...")
        server.stop()  # posts sentinel → unblocks executor.pump()

    threading.Thread(target=_watch, daemon=True).start()

    try:
        executor.pump()  # blocks main thread; dispatches all IDA API calls
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")
    finally:
        logger.info("Shutdown complete")


def cli() -> None:
    parser = argparse.ArgumentParser(description="Headless IDA RPC server")
    parser.add_argument("idb_path", help="Path to the .idb / .i64 database")
    parser.add_argument(
        "--ida-dir",
        default=environ.get("IDADIR", ""),
        help="IDA installation directory (or set IDADIR env var)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    if not args.ida_dir:
        logger.error("ERROR: --ida-dir or IDADIR env var required")
        sys.exit(1)

    if not Path(args.idb_path).exists():
        logger.error(f"ERROR: idb not found: {args.idb_path}")
        sys.exit(1)

    stop_event = Event()

    def _handle_signal(_sig, _frame) -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    main(args.idb_path, args.ida_dir, args.host, args.port, stop_event=stop_event)


if __name__ == "__main__":
    cli()
