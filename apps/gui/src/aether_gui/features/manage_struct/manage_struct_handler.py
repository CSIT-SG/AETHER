from typing import Any, Literal

import ida_funcs
import ida_kernwin
import ida_name
import idaapi
from aether_gui.runner import get_shared_worker_manager
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.logger import get_logger

logger = get_logger("manage_struct_handler")


class ManageStructHandler(ida_kernwin.action_handler_t):
    def __init__(self, mcp_client: MCPClient, operation: str) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.mcp_client = mcp_client
        self.operation = operation

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        worker_manager = get_shared_worker_manager()
        rpc_id = get_rpc_id()
        ea = ida_kernwin.get_screen_ea()
        view = ida_kernwin.get_current_viewer()
        hl = ida_kernwin.get_highlight(
            view
        )  # get_highlight returns a tuple: (highlighted_string, flags)

        if hl is None:
            logger.error("No highlighted values")
            return 0
        highlighted_string = hl[0]
        screen_ea = ida_kernwin.get_screen_ea()

        # Resolve name to effective address (ea)
        ea = ida_name.get_name_ea(screen_ea, highlighted_string)

        if ea == idaapi.BADADDR:
            logger.error(
                f"Unable to resolve {highlighted_string}. Please highlight a valid variable."
            )
            return 0

        func = ida_funcs.get_func(ea)

        if func and func.start_ea == ea:
            logger.error(
                f"cannot make struct from {func.name}, please highlight a variable instead"
            )

        task = CallToolTask()
        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="manage_struct",
            tool_args={
                "rpc_id": rpc_id,
                "operation": self.operation,
                "function_address": hex(ea),
                "var_name": highlighted_string,
            },
        )

        while not handle.done:
            if handle.error:
                logger.error(handle.error)
            logger.info(handle.results.get())

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
