from abc import ABC, abstractmethod
from typing import Any

from agents import Tool


class EvidenceAdapter[T](ABC):
    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Return the system prompt."""

    @abstractmethod
    def build_tools(self) -> list[Tool]:
        """Return the tools the grading agent may call."""

    @abstractmethod
    def run_context(self, evidence: T) -> Any | None:
        """Return the ``Runner.run`` context, or ``None`` when no context is used."""

    @abstractmethod
    def build_prompt(
        self,
        evidence: T,
        criterion: str,
        description: str,
        rubric_name: str,
    ) -> str:
        """Compose the per-criterion grading prompt from the evidence."""
