import contextlib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from aether_gui.runner import BaseTask
from aether_gui.utils.rpc_id import get_rpc_id
from aether_utils.api_client import OpenAIGateway
from agents import Agent, Runner, RunResultStreaming
from agents.mcp import MCPServerStreamableHttp
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
        self._mcp: MCPServerStreamableHttp | None = None
        self._result: RunResultStreaming | None = None

    async def run(
        self,
        mcp_url: str,
        user_prompt: str,
        ida_context: dict[str, Any],
    ) -> AsyncIterator[LLMResponse]:
        template = get_template(USER_PROMPT_TEMPLATE.name)
        user_prompt = template.render(prompt=user_prompt, ctx=ida_context)

        template = get_template(SYSTEM_PROMPT_TEMPLATE.name)
        system_prompt = template.render(rpc_id=get_rpc_id())

        self._mcp = MCPServerStreamableHttp(
            params={"url": mcp_url},
            client_session_timeout_seconds=60,
        )
        await self._mcp.__aenter__()  # type: ignore[no-untyped-call]

        try:
            agent = Agent(
                name="Chatbot",
                model=OpenAIGateway().get_model(feature="chatbot"),
                instructions=system_prompt,
                mcp_servers=[self._mcp],
            )

            self._result = Runner.run_streamed(agent, input=user_prompt, max_turns=None)

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

        if self._mcp is not None:
            with contextlib.suppress(Exception):
                await self._mcp.__aexit__(None, None, None)  # type: ignore[no-untyped-call]
            self._mcp = None
