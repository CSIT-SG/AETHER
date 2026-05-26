import inspect
import json

import uvicorn
from mcp.server import Server as MCPServer
from mcp.server.sse import SseServerTransport
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route

from .routes import HelloWorldRoute, IDAContext, ServerContext


def _parse_context_from_request(request: Request) -> ServerContext | None:
    """
    Extract IDA context from request headers.
    Validates data types silently without raising exceptions or HTTP errors.
    """
    raw = request.headers.get("X-IDA-Context")
    if raw is None:
        return None

    callback_url = request.headers.get("X-IDA-Callback-URL")
    if callback_url is None:
        return None

    try:
        ida_context = IDAContext.model_validate_json(raw)
        return ServerContext(ida=ida_context, callback_url=callback_url)

    except (ValidationError, json.JSONDecodeError):
        return None


def build_starlette_app(raw_routes: tuple[type, ...]) -> Starlette:
    # manages session UUIDs and routes inbound messages to the right client stream
    session_transport = SseServerTransport("/ida/messages/")

    async def handle_ida_client_connection(request: Request) -> Response:
        # each connecting IDA plugin instance provides its own database context
        client_ctx = _parse_context_from_request(request)

        if client_ctx is None:
            return Response("Missing or invalid X-IDA-Context header", status_code=400)

        # isolated mcp server and routes per IDA client session
        session_server = MCPServer("aether_mcp_server")

        shared_arguments = {"ctx": client_ctx}
        routes = []
        for cls in raw_routes:
            # Look up what arguments this specific child class requires
            sig = inspect.signature(cls.__init__)
            valid_params = sig.parameters.keys()

            # Filter the single variable down to only what this class accepts
            safe_args = {k: v for k, v in shared_arguments.items() if k in valid_params}

            # Instantiate the class and store it
            node_instance = cls(**safe_args)
            routes.append(node_instance)

        # open bidirectional streams for this session
        async with session_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (inbound, outbound):
            await session_server.run(
                inbound,
                outbound,
                session_server.create_initialization_options(),
            )

        return Response()

    return Starlette(
        routes=[
            Route("/ida/session", endpoint=handle_ida_client_connection, methods=["GET"]),
            Mount("/ida/requests/", app=session_transport.handle_post_message), # Route for client to send POST request for calls to server
        ]
    )


def run_server(host: str = "0.0.0.0", port: int = 8000, routes: tuple[type, ...] = (HelloWorldRoute,)) -> None:
    app = build_starlette_app(routes)
    uvicorn.run(app, host=host, port=port)
