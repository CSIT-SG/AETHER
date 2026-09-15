from typing import Any, Literal

import ida_funcs
import ida_kernwin
from aether_gui.runner import get_shared_worker_manager
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.logger import get_logger

logger = get_logger("unflatten_logger")


class UnflattenHandler(ida_kernwin.action_handler_t):
    def __init__(self, mcp_client: MCPClient) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.mcp_client = mcp_client

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        worker_manager = get_shared_worker_manager()
        rpc_id = get_rpc_id()
        ea = ida_kernwin.get_screen_ea()
        func_ea = ida_funcs.get_func(ea).start_ea

        task = CallToolTask()
        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="unflatten_function",
            tool_args={
                "rpc_id": rpc_id,
                "address": hex(func_ea),
                "custom_prompt": None,
            },
        )

        while not handle.done:
            if handle.error:
                logger.error(handle.error)
            logger.info(handle.results.get())

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
