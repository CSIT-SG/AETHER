from typing import Any

import uvicorn
from mcp.server import Server as MCPServer
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route

from .routes import HelloWorldRoute, IDAContext, ServerContext


def build_server_context(
    idb_path: str,
    architecture: str | None = None,
    bitness: int | None = None,
    entry_point: int | None = None,
    segment_map: list[dict[str, Any]] | None = None,
    functions: list[dict[str, Any]] | None = None,
) -> ServerContext:
    ida_context = IDAContext(
        idb_path=idb_path,
        architecture=architecture,
        bitness=bitness,
        entry_point=entry_point,
        segment_map=segment_map or [],
        functions=functions or [],
    )
    return ServerContext(ida=ida_context)


def build_starlette_app(ctx: ServerContext) -> Starlette:
    # one shared SSE transport — manages all session UUIDs and message routing
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> Response:
        # fresh server per client — isolated request_handlers
        server = MCPServer("aether_mcp_server")

        # register routes onto this client's server with the shared context
        routes = [HelloWorldRoute(ctx)]
        for route in routes:
            route.register(server)

        # open this client's SSE streams
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            # blocks for the lifetime of this client's connection
            await server.run(
                streams[0],
                streams[1],
                server.create_initialization_options(),
            )

        return Response()

    return Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )


def run_server(ctx: ServerContext, host: str = "0.0.0.0", port: int = 8000) -> None:
    app = build_starlette_app(ctx)
    uvicorn.run(app, host=host, port=port)
