from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

type LLMResponse = TextDelta | ReasoningDelta | ToolCall | ToolOutput


class LLMOutput(ABC):
    """Abstract class for different LLM outputs"""

    @abstractmethod
    def __str__(self) -> str: ...


@dataclass
class TextDelta(LLMOutput):
    """A chunk of streamed text output from the LLM."""

    delta: str

    def __str__(self) -> str:
        return self.delta


@dataclass
class ReasoningDelta(LLMOutput):
    """A chunk of streamed reasoning from the LLM (o1/o3 models)."""

    delta: str

    def __str__(self) -> str:
        return f"[Reasoning]: {self.delta}"


@dataclass
class ToolCall(LLMOutput):
    """The LLM has committed to a tool call."""

    name: str
    arguments: str | None
    call_id: str

    def __str__(self) -> str:
        return f"Calling tool '{self.name}' with args: {self.arguments if self.arguments else 'No arguments provided'}"


@dataclass
class ToolOutput(LLMOutput):
    """A tool executed and returned a result."""

    output: str
    call_id: str

    def __str__(self) -> str:
        return f"Result: {self.output}"
