
from typing import Any

import httpx
from mcp.server import Server as BaseServer
from openai import AsyncOpenAI

from .routes import HelloWorldRoute, IDAContext, ServerContext

# TODO: find better way to initiate server but this will have to do for now
# Should export build_server_context and build_server to plugin and then call from there given context and stuff
# Remove the None typing as its only to initiate the server for testing

def build_server_context(
        idb_path: str | None = None,
        segment_map: list[dict[str, Any]] | None = None,
        http_client: httpx.AsyncClient | None = None,
        openai_client: AsyncOpenAI | None = None) -> ServerContext:

    ida_context = IDAContext()

    return ServerContext(ida_context, http_client, openai_client)



def build_server(ctx: ServerContext) -> BaseServer:
    server = BaseServer("aether_mcp_server")

    list_routes = [HelloWorldRoute(ctx)]

    for route in list_routes:
        route.register(server)
    return server
