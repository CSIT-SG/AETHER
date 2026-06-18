from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

from .tools import app_provider
from .utils.rpc_discovery import rpc_lifespan

mcp_app = FastMCP("AETHER Backend", providers=[app_provider], lifespan=rpc_lifespan).http_app(
    path="/"
)

app = Starlette(
    routes=[
        Mount("/mcp", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,  # Required for Streamable HTTP
)
