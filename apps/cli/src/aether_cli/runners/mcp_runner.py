import uvicorn
from aether_utils.get_port import get_port
from aether_utils.logger import get_logger

logger = get_logger("mcp_headless")


def mcp_runner(host: str = "127.0.0.1") -> None:
    port = get_port(host)
    logger.info(f"MCP server started at {host}:{port}")
    uvicorn.run("aether_backend.server:app", port=port, log_level="warning")
