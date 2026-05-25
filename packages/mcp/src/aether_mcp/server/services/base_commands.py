from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.types import CallToolResult, GetPromptResult, Prompt, Resource, ResourceTemplate, Tool

# https://modelcontextprotocol.io/docs/develop/build-server#core-mcp-concepts


@dataclass(frozen=True)
class ToolCommand:
    tool: Tool
    handler: Callable[..., Awaitable[CallToolResult]]


@dataclass(frozen=True)
class ResourceCommand:
    resource: Resource
    handler: Callable[..., Awaitable[Iterable[ReadResourceContents]]]

@dataclass(frozen=True)
class ResourceTemplateCommand:
    template: ResourceTemplate


@dataclass(frozen=True)
class PromptCommand:
    prompt: Prompt
    handler: Callable[..., Awaitable[GetPromptResult]]
