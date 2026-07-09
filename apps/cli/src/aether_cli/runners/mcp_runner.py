import socket

import uvicorn
from aether_utils.get_port import get_port
from aether_utils.logger import get_logger

logger = get_logger("AETHER_CLI_MCP")


def _free_port(h, p):
    try:
        socket.create_connection((h, p), timeout=2.0).close()
        return False
    except OSError:
        return True


def mcp_runner(host: str = "127.0.0.1") -> None:
    port = 8000
    if not _free_port(host, port):
        port = get_port(host)

    logger.info(f"MCP server started at {host}:{port}")
    uvicorn.run("aether_backend.server:app", port=port, log_level="warning")
