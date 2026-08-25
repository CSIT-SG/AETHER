from pathlib import Path

from agents import Agent, ModelSettings

from aether_utils.api_client import OpenAIGateway
from aether_utils.get_content import get_content


def get_compacting_agent(model: str | None = None) -> Agent:
    """Get the compacting agent with the system prompt loaded from the content directory."""
    SYSTEM_PROMPT = get_content(Path(__file__).parent, "prompt.md")
    return Agent(
        name="Compacting Agent",
        model=OpenAIGateway().get_model(
            feature="compact_history",
            model_name=model,
        ),
        instructions=SYSTEM_PROMPT,
        model_settings=ModelSettings(tool_choice="none"),
    )
