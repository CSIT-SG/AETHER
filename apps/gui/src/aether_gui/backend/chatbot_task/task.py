from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from aether_gui.runner import BaseTask

from ..llm_client import LLMResponse, OpenAIClient
from .constants import get_template

SYSTEM_PROMPT = Path(__file__).parent / "prompts" / "system_prompt.md"
TEMPLATE_PATH = Path(__file__).parent / "prompts" / "user_prompt.md.jinja"


class ChatBotTask(BaseTask[LLMResponse]):
    def __init__(
        self,
        llm_client: OpenAIClient,
        mcp_url: str,
        user_prompt: str,
        ida_context: dict[str, Any],
        template_path: Path = TEMPLATE_PATH,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        self.llm_client = llm_client
        self.mcp_url = mcp_url
        self.user_prompt = user_prompt
        self.ida_context = ida_context
        self.template_path = template_path

    async def run(self) -> AsyncIterator[LLMResponse]:
        template = get_template(self.template_path.name)
        prompt = template.render(prompt=self.user_prompt, ctx=self.ida_context)

        system_prompt = SYSTEM_PROMPT.read_text(encoding="utf-8")

        async for event in self.llm_client.submit(
            system_prompt=system_prompt,
            user_prompt=prompt,
            url=self.mcp_url,
        ):
            yield event

    async def close(self) -> None:
        pass
