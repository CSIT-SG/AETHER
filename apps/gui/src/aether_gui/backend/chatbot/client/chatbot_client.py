from __future__ import annotations

from collections.abc import AsyncIterator

from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

from .types import LLMResponse, ReasoningDelta, TextDelta, ToolCall, ToolOutput

config = get_config()


class ChatbotClient:
    async def submit(
        self,
        system_prompt: str,
        user_prompt: str,
        url: str,
    ) -> AsyncIterator[LLMResponse]:
        async with MCPServerStreamableHttp(
            params={
                "url": url,
            },
            client_session_timeout_seconds=60,
        ) as mcp:
            agent = Agent(
                name="Chatbot",
                model=OpenAIGateway().get_model(
                    feature="chatbot",
                ),
                instructions=system_prompt,
                mcp_servers=[mcp],
            )

            result = Runner.run_streamed(agent, input=user_prompt)

            async for event in result.stream_events():
                if event.type == "raw_response_event":
                    raw = event.data
                    match raw.type:
                        case "response.output_text.delta":
                            yield TextDelta(delta=raw.delta)
                        case "response.reasoning_summary_text.delta":
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
