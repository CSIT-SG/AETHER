from aether_backend.utils.effect import Program, effectful
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .web_request import fetch_url_stream


@tool(
    annotations=ToolAnnotations(title="Fetch URL", readOnlyHint=True, destructiveHint=False),
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def fetch_url(url: str) -> Program:
    """Stream a URL response with progress updates."""
    async for effect in fetch_url_stream(url):
        yield effect
