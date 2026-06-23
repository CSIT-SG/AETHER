from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

from .models import Message, PublishedEvent
from .agent.base import AgentContext, BaseAgent, CallbackAgent
from ..services.memory import MemoryStore
from ..services.planning import Plan, PlanManager
from ..tools import ContextTool, MemoryTool, PlanningTool, RuntimeTool


MANDATORY_TOOL_NAMES = ("context", "memory", "planning")


class MultiAgentRuntime:
    def __init__(self):
        self._agents: dict[str, BaseAgent] = {}
        self._mailboxes: dict[str, deque[Message]] = defaultdict(deque)
        self._history: list[Message] = []
        self._events: list[PublishedEvent] = []
        self._agent_tools: dict[str, dict[str, RuntimeTool]] = {}
        self._agent_context: dict[str, dict[str, Any]] = defaultdict(dict)
        self._agent_conversation_histories: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._agent_memory_stores: dict[str, MemoryStore] = defaultdict(MemoryStore)
        self._agent_plan_managers: dict[str, PlanManager] = defaultdict(PlanManager)
        self.shared_state: dict[str, Any] = {}

    @property
    def agents(self) -> dict[str, BaseAgent]:
        return dict(self._agents)

    @property
    def history(self) -> list[Message]:
        return list(self._history)

    @property
    def events(self) -> list[PublishedEvent]:
        return list(self._events)

    def add_agent(self, agent: BaseAgent) -> BaseAgent:
        if agent.agent_id in self._agents:
            raise ValueError(f"Agent '{agent.agent_id}' is already registered.")
        self._agents[agent.agent_id] = agent
        self._agent_tools[agent.agent_id] = self._build_toolset(agent.tools)
        agent.on_registered(AgentContext(self, agent.agent_id))
        return agent

    def create_agent(
        self,
        agent_id: str,
        handler,
        *,
        description: str = "",
        tools: list[RuntimeTool] | None = None,
    ) -> CallbackAgent:
        agent = CallbackAgent(agent_id, handler, description=description, tools=tools)
        self.add_agent(agent)
        return agent

    def get_agent_tools(self, agent_id: str) -> dict[str, RuntimeTool]:
        if agent_id not in self._agent_tools:
            raise KeyError(f"Unknown agent '{agent_id}'.")
        return dict(self._agent_tools[agent_id])

    def get_agent_memory_store(self, agent_id: str) -> MemoryStore:
        if agent_id not in self._agents:
            raise KeyError(f"Unknown agent '{agent_id}'.")
        return self._agent_memory_stores[agent_id]

    def get_agent_context(self, agent_id: str) -> dict[str, Any]:
        if agent_id not in self._agents:
            raise KeyError(f"Unknown agent '{agent_id}'.")
        return self._agent_context[agent_id]

    def clear_agent_context(self, agent_id: str) -> None:
        self.get_agent_context(agent_id).clear()

    def get_agent_conversation_history(self, agent_id: str) -> list[dict[str, Any]]:
        if agent_id not in self._agents:
            raise KeyError(f"Unknown agent '{agent_id}'.")
        return self._agent_conversation_histories[agent_id]

    def set_agent_conversation_history(self, agent_id: str, history: list[dict[str, Any]]) -> None:
        if agent_id not in self._agents:
            raise KeyError(f"Unknown agent '{agent_id}'.")
        self._agent_conversation_histories[agent_id] = history

    def clear_agent_conversation_history(self, agent_id: str) -> None:
        self.get_agent_conversation_history(agent_id).clear()

    def get_agent_plan_manager(self, agent_id: str) -> PlanManager:
        if agent_id not in self._agents:
            raise KeyError(f"Unknown agent '{agent_id}'.")
        return self._agent_plan_managers[agent_id]

    def get_agent_plan(self, agent_id: str) -> Plan | None:
        return self.get_agent_plan_manager(agent_id).active_plan

    def clear_agent_plan(self, agent_id: str) -> None:
        self.get_agent_plan_manager(agent_id).clear()

    def _build_toolset(self, configured_tools: list[RuntimeTool]) -> dict[str, RuntimeTool]:
        toolset: dict[str, RuntimeTool] = {
            "planning": PlanningTool(),
            "context": ContextTool(),
            "memory": MemoryTool(),
        }

        for tool in configured_tools:
            cloned = tool.clone()
            if cloned.name in MANDATORY_TOOL_NAMES:
                continue
            if cloned.name in toolset:
                raise ValueError(f"Tool '{cloned.name}' is configured more than once.")
            toolset[cloned.name] = cloned

        return toolset

    def send(
        self,
        sender: str,
        recipient: str,
        content: Any,
        *,
        topic: str = "message",
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        if recipient not in self._agents:
            raise KeyError(f"Unknown recipient '{recipient}'.")

        message = Message(
            sender=sender,
            recipient=recipient,
            content=content,
            topic=topic,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )
        self._mailboxes[recipient].append(message)
        self._history.append(message)
        return message

    def broadcast(
        self,
        sender: str,
        content: Any,
        *,
        topic: str = "broadcast",
        metadata: dict[str, Any] | None = None,
        exclude: Iterable[str] | None = None,
    ) -> list[Message]:
        excluded = set(exclude or ())
        sent: list[Message] = []
        for recipient in self._agents:
            if recipient == sender or recipient in excluded:
                continue
            sent.append(
                self.send(
                    sender,
                    recipient,
                    content,
                    topic=topic,
                    metadata=metadata,
                )
            )
        return sent

    def publish(self, publisher: str, key: str, value: Any) -> None:
        self.shared_state[key] = value
        self._events.append(PublishedEvent(key=key, value=value, publisher=publisher))

    def has_pending_messages(self) -> bool:
        return any(self._mailboxes.values())

    def step(self) -> bool:
        for agent_id, agent in self._agents.items():
            mailbox = self._mailboxes[agent_id]
            if not mailbox:
                continue
            message = mailbox.popleft()
            agent.handle_message(message, AgentContext(self, agent_id))
            return True
        return False

    def run(self, max_steps: int = 1_000) -> int:
        steps = 0
        while steps < max_steps and self.step():
            steps += 1
        return steps
