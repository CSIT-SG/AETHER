from aether_utils.logger import get_logger

import aether_rpc.capabilities as caps
from aether_rpc.executors.gui_executor import GUIExecutor
from aether_rpc.server import RPCServer

CAPABILITIES = [getattr(caps, c)() for c in caps.__all__]
logger = get_logger("rpc_gui_plugin")
executor = GUIExecutor()

gui_server = RPCServer("gui", executor, CAPABILITIES)
