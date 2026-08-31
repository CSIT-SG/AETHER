from aether_utils.logger import get_logger

from aether_rpc.capabilities import load_capabilities
from aether_rpc.executors.gui_executor import GUIExecutor
from aether_rpc.server import RPCServer

CAPABILITIES = load_capabilities()
executor = GUIExecutor()

logger = get_logger("rpc_gui_plugin")


class GUIRPCServer:
    def __init__(self, file_id: str):
        self.file_id = file_id
        self.server = RPCServer(id=file_id, executor=executor, capabilities=CAPABILITIES)

    def start(self):
        self.server.start()
        logger.info(f"GUI RPC server for file_id {self.file_id} started on port {self.server.port}")

    def stop(self):
        self.server.stop()
        logger.info(f"GUI RPC server for file_id {self.file_id} stopped")
