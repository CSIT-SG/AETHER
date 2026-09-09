from __future__ import annotations

import json
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
        return f"_[Reasoning]_: {self.delta}"


@dataclass
class ToolCall(LLMOutput):
    """The LLM has committed to a tool call."""

    name: str
    arguments: str | None
    call_id: str

    def __str__(self) -> str:
        args = self.arguments or ""
        try:
            # arguments is likely a JSON string, but if it isn't, just return it as-is
            args_json = json.loads(args)
            args = json.dumps(args_json, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass
        return f"_[Tool Call `{self.call_id}`]_:\t`{self.name}({args})`"


@dataclass
class ToolOutput(LLMOutput):
    """A tool executed and returned a result."""

    output: str
    call_id: str

    def __str__(self) -> str:
        output = self.output.strip()
        try:
            # output may or may not be JSON, but if it is, format it for better readability
            output_json = json.loads(output)
            output = json.dumps(output_json, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass
        return f"_[Tool Output `{self.call_id}`]_:\n```{output}```"
