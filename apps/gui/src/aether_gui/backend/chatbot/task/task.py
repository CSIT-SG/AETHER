import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from concurrent.futures import Future
from pathlib import Path
from typing import Any

from aether_gui.runner import BaseTask
from aether_gui.utils.chat_session import ChatSession
from aether_gui.utils.mcp import MCPClient, SubtoolProgressBuffer, merge_aiterators
from aether_gui.utils.rpc_id import get_rpc_id
from aether_gui.utils.ui import deserialise_call_tool_result
from aether_utils.api_client import OpenAIGateway
from aether_utils.config import get_config
from agents import (
    Agent,
    FunctionTool,
    RunContextWrapper,
    Runner,
    RunResultStreaming,
)
from agents import (
    Tool as AgentTool,
)
from fastmcp_tasks import ToolTask
from mcp_types import Tool as MCPTool
from openai.types.responses import (
    ResponseReasoningSummaryTextDeltaEvent,
    ResponseTextDeltaEvent,
)

from .constants import get_template
from .types import LLMResponse, ReasoningDelta, SubtoolTrace, TextDelta, ToolCall, ToolOutput

SYSTEM_PROMPT_TEMPLATE = Path(__file__).parent / "content" / "system_prompt.md.jinja"
USER_PROMPT_TEMPLATE = Path(__file__).parent / "content" / "user_prompt.md.jinja"


async def _stream_llm_responses(
    result: RunResultStreaming,
    buffer: SubtoolProgressBuffer | None = None,
) -> AsyncIterator[LLMResponse]:
    """Map a streamed agent run into renderable LLMResponse values."""
    try:
        async for event in result.stream_events():
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
        if buffer is not None:
            buffer.close()


async def _stream_subtool_responses(
    buffer: SubtoolProgressBuffer,
) -> AsyncIterator[LLMResponse]:
    async for message in buffer.traces():
        yield SubtoolTrace(message)


class ChatBotTask(BaseTask[LLMResponse]):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__()
        self._mcp: MCPClient | None = None
        self._result: RunResultStreaming | None = None
        self._active_tool_tasks: set[ToolTask] = set()

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
        buffer = SubtoolProgressBuffer(mcp_client)

        config = get_config()
        try:
            agent = Agent(
                name="Chatbot",
                model=OpenAIGateway().get_model(
                    model_name=config.subagents.chatbot_model if config.subagents else None,
                    feature="chatbot",
                ),
                instructions=system_prompt,
                tools=tools,
            )
            self._result = Runner.run_streamed(
                agent, input=user_prompt, max_turns=None, session=session.chat_session
            )

            merged = merge_aiterators(
                _stream_llm_responses(self._result, buffer),
                _stream_subtool_responses(buffer),
            )
            async for item in merged:
                yield item
        finally:
            await self._cleanup()

    async def close(self) -> None:
        await self._cleanup()

    async def _cleanup(self) -> None:
        tasks = list(self._active_tool_tasks)
        self._active_tool_tasks.clear()
        for task in tasks:
            with contextlib.suppress(Exception):
                await task.cancel()
        if self._result is not None:
            try:
                self._result.cancel()
                async for _ in self._result.stream_events():
                    pass
            except (Exception, asyncio.CancelledError):
                pass
            self._result = None

    async def list_mcp_tools_as_agent_tools(self, client: MCPClient) -> list[AgentTool]:
        """List MCP tools and wrap each as an Agents SDK FunctionTool."""
        tools = await client.list_tools()
        return [self._wrap_mcp_tool(client, tool) for tool in tools]

    def _wrap_mcp_tool(self, client: MCPClient, tool: MCPTool) -> AgentTool:
        """Wrap a single MCP tool as an Agents SDK FunctionTool."""

        async def on_invoke(_ctx: RunContextWrapper[Any], args_json: str) -> str:
            args = json.loads(args_json) if args_json else {}
            task = await client.call_fastmcp_tool_task(tool_name=tool.name, args=args)
            self._active_tool_tasks.add(task)
            poller = asyncio.create_task(client.poll_subtool_traces(task))
            try:
                result = await task.result()
                return deserialise_call_tool_result(result)
            except Exception as e:
                return f"Tool {tool.name!r} is unavailable: {e}"
            finally:
                self._active_tool_tasks.discard(task)
                poller.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await poller

        return FunctionTool(
            name=tool.name,
            description=tool.description or "",
            params_json_schema=tool.input_schema,
            on_invoke_tool=on_invoke,
            strict_json_schema=False,
        )
