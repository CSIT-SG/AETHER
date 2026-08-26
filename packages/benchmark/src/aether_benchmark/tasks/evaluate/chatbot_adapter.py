from pathlib import Path

from aether_utils.get_content import get_content
from agents import Tool

from .adapter import EvidenceAdapter


class ChatbotEvidenceAdapter(EvidenceAdapter[str]):
    """Grades chatbot conversation transcript."""

    @property
    def system_prompt(self) -> str:
        return get_content(Path(__file__).parent, "chatbot_evaluate_prompt.md")

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
