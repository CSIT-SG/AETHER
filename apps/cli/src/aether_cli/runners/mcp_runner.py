import uvicorn
from aether_utils.logger import get_logger

from aether_cli.utils import get_port

logger = get_logger("mcp_headless")


def mcp_runner(host: str = "127.0.0.1") -> None:
    port = get_port(host)
    uvicorn.run("aether_backend.server:app", port=port, log_level="warning")
    logger.info(f"MCP server started at {host}:{port}")
