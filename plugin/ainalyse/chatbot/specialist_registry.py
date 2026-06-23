from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(slots=True)
class SpecialistAgentSpec:
    agent_id: str
    capability: str
    description: str = ""


class SpecialistAgentRegistry:
    def __init__(self):
        self._specs: dict[str, SpecialistAgentSpec] = {}
        self._factories: dict[str, Callable[[], object]] = {}

    def register(self, spec: SpecialistAgentSpec, factory: Callable[[], object]) -> None:
        if not spec.agent_id.strip():
            raise ValueError("agent_id cannot be empty")
        if not spec.capability.strip():
            raise ValueError("capability cannot be empty")
        if spec.agent_id in self._specs:
            raise ValueError(f"Specialist agent '{spec.agent_id}' is already registered")
        self._specs[spec.agent_id] = spec
        self._factories[spec.agent_id] = factory

    def contains(self, agent_id: str) -> bool:
        return agent_id in self._specs

    def get(self, agent_id: str) -> SpecialistAgentSpec:
        try:
            return self._specs[agent_id]
        except KeyError as exc:
            raise KeyError(f"Unknown specialist agent '{agent_id}'") from exc

    def list_specs(self) -> list[SpecialistAgentSpec]:
        return [self._specs[agent_id] for agent_id in sorted(self._specs.keys())]

    def create(self, agent_id: str) -> object:
        try:
            factory = self._factories[agent_id]
        except KeyError as exc:
            raise KeyError(f"Unknown specialist agent '{agent_id}'") from exc
        return factory()
