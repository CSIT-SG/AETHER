import asyncio

import mcp.server.stdio

from .server import build_server, build_server_context


# TODO: This is just for testing but can be used for future reference on how to start server
async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        ctx = build_server_context()
        server = build_server(ctx)
        await server.run(read, write, server.create_initialization_options())

asyncio.run(main())
