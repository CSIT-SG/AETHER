from typing import Any, Literal

import ida_funcs
import ida_hexrays
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

    def is_valid_local_var(self, ea: int, name: str) -> bool:
        """
        Check if `name` is a valid Hex-Rays local (stack or register) variable
        for the function containing `ea`.
        """
        func: ida_funcs.func_t | None = ida_funcs.get_func(ea)
        if func is None:
            return False

        try:
            cfunc = ida_hexrays.decompile(func)
        except ida_hexrays.DecompilationFailure:
            return False

        if cfunc is None:
            return False

        return any(lv.name == name for lv in cfunc.get_lvars())

    def is_valid_global_var(self, name: str) -> bool:
        """
        Check if `name` resolves to a valid global address (function, data, etc).
        """
        return ida_name.get_name_ea(idaapi.BADADDR, name) != idaapi.BADADDR

    def is_function(self, name: str) -> bool:
        """
        Check if `name` resolves to an address that is the start of a
        recognized function (defined or a known/imported one).
        """
        name = name.strip()
        if not name:
            return False

        ea: int = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return False

        return ida_funcs.get_func(ea) is not None

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        worker_manager = get_shared_worker_manager()
        rpc_id = get_rpc_id()
        ea = ida_kernwin.get_screen_ea()
        view = ida_kernwin.get_current_viewer()
        hl = ida_kernwin.get_highlight(
            view
        )  # get_highlight returns a tuple: (highlighted_string, flags)

        if hl is None or len(hl) == 0:
            logger.error("No highlighted values")
            return 0

        highlighted_string = hl[0]

        if not (
            self.is_valid_local_var(ea, highlighted_string)
            or self.is_valid_global_var(highlighted_string)
        ):
            logger.error(
                f"Unable to resolve {highlighted_string}, please highlight a valid variable."
            )
            return 0

        if self.is_function(highlighted_string):
            logger.error(f"{highlighted_string} is a function, please highlight a variable instead")
            return 0

        func_ea = ida_funcs.get_func(ea).start_ea
        task = CallToolTask()
        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="manage_struct",
            tool_args={
                "rpc_id": rpc_id,
                "operation": self.operation,
                "function_address": hex(func_ea),
                "var_name": highlighted_string,
                "local_var": self.is_valid_local_var(ea, highlighted_string),
            },
        )

        worker_manager.consume(
            handle=handle,
            on_event=lambda result: logger.info(result),
            on_error=lambda error: logger.error(error),
        )

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
