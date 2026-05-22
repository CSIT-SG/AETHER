
from mcp.server import Server as BaseServer

from . import routes


def build_server() -> BaseServer:
    server = BaseServer("aether_mcp_server")

    list_routes: list[routes.AbstractMCPRoute] = [
        getattr(routes, route) for route in routes.__all__
    ]

    for route in list_routes:
        route.register(server)
    return server
