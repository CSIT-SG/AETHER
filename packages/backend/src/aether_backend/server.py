from aether_utils.config import get_config
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

from .constants import ToolTags
from .tools import app_provider
from .utils.rpc_discovery import rpc_lifespan


def get_disabled_tags() -> set[str]:
    """Determine which tool tags should be disabled based on the configuration."""
    config = get_config()
    disabled_tags = set()

    if not config.debug:
        disabled_tags.add(ToolTags.DEBUG)

    return disabled_tags


mcp = FastMCP("AETHER Backend", providers=[app_provider], lifespan=rpc_lifespan)

mcp.disable(tags=get_disabled_tags())

mcp_app = mcp.http_app(path="/")

app = Starlette(
    routes=[
        Mount("/mcp", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,  # Required for Streamable HTTP
)
