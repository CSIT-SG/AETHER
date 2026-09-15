import json
from typing import Any, Literal

import ida_funcs
import ida_kernwin
from aether_gui.runner import get_shared_worker_manager
from aether_gui.utils.mcp import CallToolTask, MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.logger import get_logger
from fastmcp.client.client import CallToolResult
from mcp_types import TextContent

from .components import UnflattenOutputWindow

logger = get_logger("unflatten_logger")


class UnflattenHandler(ida_kernwin.action_handler_t):
    def __init__(self, mcp_client: MCPClient) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.mcp_client = mcp_client

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        worker_manager = get_shared_worker_manager()
        view = UnflattenOutputWindow()
        view.show()
        rpc_id = get_rpc_id()
        ea = ida_kernwin.get_screen_ea()
        func_ea = ida_funcs.get_func(ea).start_ea
        func_name = ida_funcs.get_func_name(func_ea)
        task = CallToolTask()
        handle = worker_manager.submit(
            task,
            mcp_client=self.mcp_client,
            tool_name="unflatten_function",
            tool_args={
                "rpc_id": rpc_id,
                "function_name": func_name,
                "custom_prompt": None,
            },
        )

        worker_manager.consume(
            handle=handle, on_event=lambda result: view.set_text(self._deserialize_flat(result))
        )

        return 0

    def _deserialize_flat(self, result: CallToolResult) -> str:
        """Flatten a tool result into the text handed to both the LLM and the UI."""
        texts = [block.text for block in result.content if isinstance(block, TextContent)]
        if texts:
            return "\n".join(texts)
        if result.structured_content is not None:
            try:
                return json.dumps(result.structured_content)
            except (TypeError, ValueError):
                pass
        return str(result)

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
