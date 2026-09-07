from __future__ import annotations

import ast
import json
import re
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
        # For now, output will be stringed to ensure the `success` context isn't lost
        # We can select `result` if we don't need the dict object.
        # processed = str(self._parse_call_tool_result_text(self.output))
        processed = str(self._parse_call_tool_result_text(self.output))
        return f"Result: {processed}"

    @staticmethod
    def _parse_call_tool_result_text(repr_str: str) -> dict[str, bool] | str:
        """Extract and JSON-decode the `text` field from a CallToolResult repr string.

        Args:
            repr_str: `CallToolResult` string with `TextContent` in the `content` key

        Returns:
            The decoded data object resulting from parsing the JSON-encoded
            string found within the `text` attribute.

            For example:
            Input:
            CallToolResult(content=[TextContent(type='text', text='"{"result": "module 'ida_ida' has no attribute 'inf_get'", "success": false}"', annotations=None, meta=None)], ...)

            Returns:
            {"result": "module 'ida_ida' has no attribute 'inf_get'", "success": false}

        Raises:
            If regex doesn't match, it'll return a string by default.
        """
        # [NOTE] Please refactor once mcp implements easier referencing
        match = re.search(r"text=('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")", repr_str)
        if not match:
            return repr_str
        raw_text = ast.literal_eval(match.group(1))
        return json.loads(json.loads(raw_text))
