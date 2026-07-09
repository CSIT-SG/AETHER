import uvicorn
from aether_utils.get_port import get_port
from aether_utils.logger import get_logger

logger = get_logger("AETHER_CLI_MCP")


def mcp_runner(host: str = "127.0.0.1") -> None:
    port = 8000

    logger.info(f"MCP server started at {host}:{port}")
    try:
        uvicorn.run("aether_backend.server:app", port=port, log_level="warning")
    except OSError:
        port = get_port(host)
        logger.info(f"Port was taken, trying again at {host}:{port}")
        uvicorn.run("aether_backend.server:app", port=port, log_level="warning")
