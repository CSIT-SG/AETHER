import importlib
import signal
import sys
import threading
from threading import Event

from aether_utils.configure_ida import configure_ida
from aether_utils.file_id import file_id
from aether_utils.get_port import get_port
from aether_utils.logger import get_logger

logger = get_logger("AETHER_CLI.RPC")


def rpc_runner(
    idb_path: str,  # can also be the actual binary path
    ida_install_dir: str,
    host: str = "127.0.0.1",
) -> None:
    configure_ida(ida_install_dir)

    import aether_rpc.capabilities as caps
    from aether_rpc.executors.headless_executor import HeadlessExecutor
    from aether_rpc.server import RPCServer

    executor = HeadlessExecutor(idb_path, ida_install_dir)
    capabilities = [
        getattr(importlib.import_module(module_path, caps.__name__), name)()
        for name, module_path in caps.EXPORTS.items()
    ]

    port = get_port(host)

    server = RPCServer(file_id(idb_path), executor, capabilities, host=host, port=port)
    server.start()  # calls executor.startup() on this (main) thread

    logger.info(f"Headless IDA RPC server started on port {server.port}")

    stop_event = Event()

    def _handle_signal(_sig: int, _frame: object) -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, _handle_signal)

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
