from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from aether_gui.runner import BaseTask
from aether_gui.utils.rpc_id import get_rpc_id

from ..llm_client import LLMResponse, OpenAIClient
from .constants import get_template

SYSTEM_PROMPT_TEMPLATE = Path(__file__).parent / "prompts" / "system_prompt.md.jinja"
USER_PROMPT_TEMPLATE = Path(__file__).parent / "prompts" / "user_prompt.md.jinja"


class ChatBotTask(BaseTask[LLMResponse]):
    def __init__(self) -> None:
        super().__init__()

    async def run(
        self,
        llm_client: OpenAIClient,
        mcp_url: str,
        user_prompt: str,
        ida_context: dict[str, Any],
    ) -> AsyncIterator[LLMResponse]:
        template = get_template(USER_PROMPT_TEMPLATE.name)
        user_prompt = template.render(prompt=user_prompt, ctx=ida_context)

        template = get_template(SYSTEM_PROMPT_TEMPLATE.name)
        system_prompt = template.render(rpc_id=get_rpc_id())

        async for event in llm_client.submit(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            url=mcp_url,
        ):
            yield event

    async def close(self) -> None:
        pass
