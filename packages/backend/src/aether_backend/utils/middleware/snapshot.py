from typing import Any, cast

from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from aether_utils.config import get_config
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

from .constants import RPC_ARGUMENT

config = get_config()


class SnapshotMiddleware(Middleware):
    async def on_call_tool(self, context: MiddlewareContext, call_next: Any) -> ToolResult:
        """Middleware hook that is called before a tool is executed.

        This method checks if the tool being executed has the destructive hint or not.
        If it does, takes snapshot of current IDA database and then continues the execution of the tool.
        Else, just executes the tool.

        Args:
            ctx (MiddlewareContext): The context of the middleware call, which
                contains information about the tool being executed and its arguments.
        """
        if not config.backup:
            return await call_next(context)

        tool_context = context.fastmcp_context
        if tool_context is None:
            return await call_next(context)

        tool = await tool_context.fastmcp.get_tool(context.message.name)
        if tool is None:
            return await call_next(context)

        annotations = tool.annotations
        is_destructive = annotations and annotations.destructiveHint

        if is_destructive:
            registry = cast(RPCRegistry, tool_context.lifespan_context[RPC_REGISTRY_KEY])
            service = await registry.get(context.message.arguments[RPC_ARGUMENT])
            if service:
                service.take_snapshot()

        return await call_next(context)
