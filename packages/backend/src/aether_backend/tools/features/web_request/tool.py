from aether_backend.utils.effect import Program, effectful
from fastmcp.tools import tool

from .web_request import fetch_url_stream


@tool  # tool is untyped in fastmcp
@effectful  # type: ignore
async def fetch_url(url: str) -> Program:
    """Stream a URL response with progress updates."""
    async for effect in fetch_url_stream(url):
        yield effect
