from pathlib import Path

from agents import Agent

from aether_utils.api_client import OpenAIGateway
from aether_utils.get_content import get_content

SYSTEM_PROMPT = get_content(Path(__file__).parent, "prompt.md")


compacting_agent = Agent(
    name="Compacting Agent",
    model=OpenAIGateway().get_model(
        feature="compact_history",
    ),
    instructions=SYSTEM_PROMPT,
)
