from .mcp_server import app_provider
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

mcp_app = FastMCP("AETHER Backend", providers=[app_provider]).http_app(path="/")

app = Starlette(
    routes=[
        Mount("/mcp", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,  # Required for Streamable HTTP
)