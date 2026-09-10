from typing import Any, Literal

import ida_funcs
import ida_kernwin
from aether_gui.runner import get_shared_worker_manager
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.logger import get_logger

logger = get_logger("generate_report_handler")


class GenerateReportHandler(ida_kernwin.action_handler_t):
    def __init__(self, mcp_client: MCPClient) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.mcp_client = mcp_client

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        worker_manager = get_shared_worker_manager()
        rpc_id = get_rpc_id()
        screen_ea = ida_kernwin.get_screen_ea()
        ea = ida_funcs.get_func(screen_ea).start_ea

        task = CallToolTask()
        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="generate_report_tool",
            tool_args={"rpc_id": rpc_id, "address": hex(ea)},
        )

        while not handle.done:
            if handle.error:
                logger.error(handle.error)
            logger.info(handle.results.get())

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
