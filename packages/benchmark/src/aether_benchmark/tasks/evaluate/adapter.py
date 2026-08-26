from abc import ABC, abstractmethod

from aether_backend.utils.get_rpc_service import AnyService
from agents import Agent


class AgentAdapter[P](ABC):
    @abstractmethod
    @staticmethod
    def build_agent(*, model: str) -> Agent:
        """Build the grading agent for this evidence type."""
        ...

    @abstractmethod
    @staticmethod
    async def run_agent(*, agent: Agent, service: AnyService, prompt_dependencies: P) -> str:
        """Run the grading agent for this evidence type."""
        ...
