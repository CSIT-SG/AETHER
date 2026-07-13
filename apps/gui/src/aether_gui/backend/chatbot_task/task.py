from collections.abc import AsyncIterator

from aether_gui.runner import BaseTask

from ..ida import IDAContext
from ..llm import LLMResponse, OpenAIClient
from .constants import TASK_TEMPLATE


class ChatBotTask(BaseTask[LLMResponse]):
    def __init__(
        self,
        llm_client: OpenAIClient,
        mcp_url: str,
        user_prompt: str,
        ida_context: IDAContext,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        self.llm_client = llm_client
        self.mcp_url = mcp_url
        self.user_prompt = user_prompt
        self.ida_context = ida_context

    async def run(self) -> AsyncIterator[LLMResponse]:  # type: ignore
        prompt = TASK_TEMPLATE.render(prompt=self.user_prompt, ctx=self.ida_context)

        async for event in self.llm_client.submit(
            user_prompt=prompt,
            url=self.mcp_url,
        ):
            yield event

    async def close(self) -> None:
        pass
