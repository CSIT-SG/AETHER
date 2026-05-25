from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from mcp.types import CallToolResult, GetPromptResult, Prompt, ReadResourceResult, Resource, Tool

# https://modelcontextprotocol.io/docs/develop/build-server#core-mcp-concepts


@dataclass(frozen=True)
class ToolCommand:
    tool: Tool
    handler: Callable[..., Coroutine[Any, Any, CallToolResult]]


@dataclass(frozen=True)
class ResourceCommand:
    resource: Resource
    handler: Callable[[str], ReadResourceResult]


@dataclass(frozen=True)
class PromptCommand:
    prompt: Prompt
    handler: Callable[..., GetPromptResult]
