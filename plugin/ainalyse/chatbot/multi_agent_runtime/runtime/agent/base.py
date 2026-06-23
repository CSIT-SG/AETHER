from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from ..models import Message
from ...tools import AgentToolbox


class AgentContext:
    def __init__(self, runtime: "MultiAgentRuntime", agent_id: str):
        self._runtime = runtime
        self.agent_id = agent_id

    @property
    def shared_state(self) -> dict[str, Any]:
        return self._runtime.shared_state

    @property
    def state(self) -> dict[str, Any]:
        return self._runtime.get_agent_context(self.agent_id)

    @property
    def memory_store(self) -> Any:
        return self._runtime.get_agent_memory_store(self.agent_id)

    @property
    def plan_manager(self) -> Any:
        return self._runtime.get_agent_plan_manager(self.agent_id)

    @property
    def tools(self) -> AgentToolbox:
        return AgentToolbox(self)

    def send(
        self,
        recipient: str,
        content: Any,
        *,
        topic: str = "message",
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        return self._runtime.send(
            self.agent_id,
            recipient,
            content,
            topic=topic,
            correlation_id=correlation_id,
            metadata=metadata,
        )

    def reply(
        self,
        message: Message,
        content: Any,
        *,
        topic: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        return self.send(
            message.sender,
            content,
            topic=topic or f"{message.topic}_reply",
            correlation_id=message.correlation_id or message.id,
            metadata=metadata,
        )

    def broadcast(
        self,
        content: Any,
        *,
        topic: str = "broadcast",
        metadata: dict[str, Any] | None = None,
    ) -> list[Message]:
        return self._runtime.broadcast(
            self.agent_id,
            content,
            topic=topic,
            metadata=metadata,
        )

    def publish(self, key: str, value: Any) -> None:
        self._runtime.publish(self.agent_id, key, value)


class BaseAgent(ABC):
    def __init__(self, agent_id: str, description: str = "", *, tools: list["RuntimeTool"] | None = None):
        self.agent_id = agent_id
        self.description = description
        self.tools = list(tools or [])

    def on_registered(self, ctx: AgentContext) -> None:
        pass

    @abstractmethod
    def handle_message(self, message: Message, ctx: AgentContext) -> None:
        raise NotImplementedError


class CallbackAgent(BaseAgent):
    def __init__(
        self,
        agent_id: str,
        handler: Callable[["CallbackAgent", Message, AgentContext], None],
        *,
        description: str = "",
        tools: list["RuntimeTool"] | None = None,
    ):
        super().__init__(agent_id=agent_id, description=description, tools=tools)
        self._handler = handler

    def handle_message(self, message: Message, ctx: AgentContext) -> None:
        self._handler(self, message, ctx)
