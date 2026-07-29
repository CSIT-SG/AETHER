import asyncio
import json
from collections.abc import AsyncIterator
from concurrent.futures import Future
from pathlib import Path
from typing import Any

from aether_gui.runner import BaseTask
from aether_gui.utils.chat_session import ChatSession
from aether_gui.utils.mcp import MCPClient
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.api_client import OpenAIGateway
from agents import Agent, FunctionTool, RunContextWrapper, Runner, RunResultStreaming, Tool
from openai.types.responses import (
    ResponseReasoningSummaryTextDeltaEvent,
    ResponseTextDeltaEvent,
)

from .constants import get_template
from .types import LLMResponse, ReasoningDelta, TextDelta, ToolCall, ToolOutput

SYSTEM_PROMPT_TEMPLATE = Path(__file__).parent / "prompts" / "system_prompt.md.jinja"
USER_PROMPT_TEMPLATE = Path(__file__).parent / "prompts" / "user_prompt.md.jinja"


class ChatBotTask(BaseTask[LLMResponse]):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__()
        self._mcp: MCPClient | None = None
        self._result: RunResultStreaming | None = None

    async def run(
        self,
        ida_context: Future[dict[str, Any]],
        mcp_client: MCPClient,
        user_prompt: str,
        session: ChatSession,
    ) -> AsyncIterator[LLMResponse]:
        ctx = await asyncio.wait_for(asyncio.wrap_future(ida_context), timeout=30)
        template = get_template(USER_PROMPT_TEMPLATE.name)
        user_prompt = template.render(prompt=user_prompt, ctx=ctx)

        template = get_template(SYSTEM_PROMPT_TEMPLATE.name)
        system_prompt = template.render(rpc_id=get_rpc_id())

        self._mcp = mcp_client
        tools = await self.list_mcp_tools_as_agent_tools(self._mcp)

        try:
            agent = Agent(
                name="Chatbot",
                model=OpenAIGateway().get_model(feature="chatbot"),
                instructions=system_prompt,
                tools=tools,
            )
            self._result = Runner.run_streamed(
                agent, input=user_prompt, max_turns=None, session=session.chat_session
            )

            async for event in self._result.stream_events():
                if event.type == "raw_response_event":
                    raw = event.data
                    if isinstance(raw, ResponseTextDeltaEvent):
                        yield TextDelta(delta=raw.delta)
                    elif isinstance(raw, ResponseReasoningSummaryTextDeltaEvent):
                        yield ReasoningDelta(delta=raw.delta)

                elif event.type == "run_item_stream_event":
                    item = event.item
                    match item.type:
                        case "tool_call_item":
                            yield ToolCall(
                                name=item.tool_name or "",
                                arguments=getattr(item.raw_item, "arguments", None),
                                call_id=item.call_id or "",
                            )
                        case "tool_call_output_item":
                            yield ToolOutput(
                                output=str(item.output),
                                call_id=item.call_id or "",
                            )
        finally:
            await self._cleanup()

    async def close(self) -> None:
        await self._cleanup()

    async def _cleanup(self) -> None:
        if self._result is not None:
            try:
                self._result.cancel()
                async for _ in self._result.stream_events():
                    pass
            except Exception:
                pass
            self._result = None

    async def list_mcp_tools_as_agent_tools(self, client: MCPClient) -> list[Tool]:
        """List MCP tools and wrap each as an Agents SDK FunctionTool."""
        tools = await client.list_tools()
        return [self._wrap_mcp_tool(client, tool) for tool in tools]

    def _wrap_mcp_tool(self, client: MCPClient, tool: Any) -> Tool:
        """Wrap a single MCP tool as an Agents SDK FunctionTool."""

        async def on_invoke(_ctx: RunContextWrapper[Any], args_json: str) -> str:
            args = json.loads(args_json) if args_json else {}
            async for result in client.call_tool(tool_name=tool.name, args=args):
                return str(result)
            return ""

        return FunctionTool(
            name=tool.name,
            description=tool.description or "",
            params_json_schema=tool.inputSchema,
            on_invoke_tool=on_invoke,
        )
