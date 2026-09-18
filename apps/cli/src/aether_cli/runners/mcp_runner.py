import uvicorn
from aether_utils.logger import get_logger

logger = get_logger("AETHER_CLI.MCP")


def mcp_runner(host: str = "127.0.0.1", port: int = 8000) -> None:

    logger.info(f"MCP server starting at {host}:{port}")

    uvicorn.run("aether_backend.server:app", port=port, log_level="warning")
