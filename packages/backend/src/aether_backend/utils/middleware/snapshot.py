from typing import cast

from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult


class SnapshotMiddleware(Middleware):
    async def on_call_tool(self, context: MiddlewareContext, call_next) -> ToolResult:
        """Middleware hook that is called before a tool is executed.

        This method checks if the tool being executed is the "TakeSnapshot" tool.
        If it is, it performs any necessary pre-processing or validation before
        allowing the tool to execute.

        Args:
            ctx (MiddlewareContext): The context of the middleware call, which
                contains information about the tool being executed and its arguments.

        Raises:
            Exception: If any validation fails or if the tool cannot be executed.
        """

        tool_context = context.fastmcp_context
        if tool_context is None:
            return await call_next(context)

        tool = tool_context.fastmcp.get_tool(context.message.name)
        annotations = getattr(tool, "annotations", None)
        is_destructive = annotations and annotations.destructiveHint

        if is_destructive:
            registry = cast(RPCRegistry, tool_context.lifespan_context[RPC_REGISTRY_KEY])
            service = await registry.get(context.message.arguments)
            if service:
                service.take_snapshot()

        return await call_next(context)
