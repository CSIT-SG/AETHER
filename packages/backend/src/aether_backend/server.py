from aether_utils.config import get_config
from aether_utils.find_root import get_version
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

from .constants import ToolChannels
from .services.rpc_discovery import rpc_lifespan
from .tools import app_provider


def get_disabled_channels() -> set[str]:
    """Determine which tool channels should be disabled based on the configuration."""
    config = get_config()
    disabled_tags: set[str] = set()

    if not config.debug:
        disabled_tags.add(ToolChannels.DEBUG)

    if not config.experimental:
        disabled_tags.add(ToolChannels.EXPERIMENTAL)

    return disabled_tags


mcp = FastMCP(
    "AETHER Backend", providers=[app_provider], lifespan=rpc_lifespan, version=get_version()
)

mcp.disable(tags=get_disabled_channels())

mcp_app = mcp.http_app(path="/")

app = Starlette(
    routes=[
        Mount("/mcp", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,  # Required for Streamable HTTP
)
