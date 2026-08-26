from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    get_local_variables,
)
from aether_backend.utils.get_rpc_service import AnyService
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_utils.get_content import get_content
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


class IDAEvidenceAdapter(EvidenceAdapter[AnyService]):
    """Grades the IDB file using the forwarded-RPC tools."""

    system_prompt = get_content(Path(__file__).parent, "evaluate_prompt.md")

    def build_tools(self) -> list[Tool]:
        return list(
            map(
                build_subagent_tool,
                [
                    get_data_at_address,
                    get_function_pseudocode,
                    get_local_variables,
                    get_functions_called_recursively,
                ],
            )
        )

    def run_context(self, evidence: AnyService) -> SubagentToolDependencies:
        return SubagentToolDependencies(evidence)

    def build_prompt(
        self,
        evidence: AnyService,
        criterion: str,
        description: str,
        rubric_name: str,
    ) -> str:
        return f"""# Rubric: {rubric_name}
## Description

{description}

## Criterion

{criterion}

Use the available evidence to determine whether this criterion is satisfied.
"""


class ChatbotEvidenceAdapter(EvidenceAdapter[str]):
    """Grades a chatbot conversation transcript presented inline."""

    system_prompt = get_content(Path(__file__).parent, "chatbot_evaluate_prompt.md")

    def build_tools(self) -> list[Tool]:
        return []

    def run_context(self, evidence: str) -> None:
        return None

    def build_prompt(
        self,
        evidence: str,
        criterion: str,
        description: str,
        rubric_name: str,
    ) -> str:
        return f"""# Rubric: {rubric_name}
## Description

{description}

## Criterion

{criterion}

## Chatbot conversation transcript

{evidence}

Determine whether the chatbot's final answer satisfies the criterion.
"""
