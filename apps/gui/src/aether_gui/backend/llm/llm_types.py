from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


# LLM APIs expect "assistant" instead of self defined aether
class LLMRole(StrEnum):
    USER = "user"
    SYSTEM = "system"
    ASSISTANT = "assistant"
    TOOL = "tool"


type LLMResponse = TextDelta | ReasoningDelta | ToolCall | ToolOutput


@dataclass
class TextDelta:
    """A chunk of streamed text output from the LLM."""

    delta: str

    @property
    def output_string(self) -> str:
        return self.delta


@dataclass
class ReasoningDelta:
    """A chunk of streamed reasoning from the LLM (o1/o3 models)."""

    delta: str

    @property
    def output_string(self) -> str:
        return f"[Reasoning]: {self.delta}"


@dataclass
class ToolCall:
    """The LLM has committed to a tool call."""

    name: str
    arguments: str
    call_id: str

    @property
    def output_string(self) -> str:
        return f"Calling tool '{self.name}' with args: {self.arguments}"


@dataclass
class ToolOutput:
    """A tool executed and returned a result."""

    output: str
    call_id: str

    @property
    def output_string(self) -> str:
        return f"Result: {self.output}"
