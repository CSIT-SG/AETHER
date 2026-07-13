from __future__ import annotations

from collections.abc import AsyncIterator

from ..llm import LLMResponse, OpenAIClient
from .constants import SYSTEM_PROMPT, TASK_TEMPLATE
from .worker_types import WorkerTask


class WorkerRuntime:
    def __init__(self, mcp_url: str) -> None:
        self.llm_client = OpenAIClient(SYSTEM_PROMPT)
        self.mcp_url = mcp_url

    async def run_task(self, task: WorkerTask) -> AsyncIterator[LLMResponse]:
        prompt = TASK_TEMPLATE.render(prompt=task["user_prompt"], ctx=task["ida_context"])

        async for event in self.llm_client.submit(
            user_prompt=prompt,
            url=self.mcp_url,
        ):
            yield event

    async def close(self) -> None:
        pass
