import argparse

import uvicorn
from aether_utils.logger import get_logger

logger = get_logger("mcp_headless")


def main(port: int, reload: bool) -> None:
    uvicorn.run("aether_backend.server:app", port=port, reload=reload)


def cli() -> None:
    parser = argparse.ArgumentParser(description="Headless IDA MCP server")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--no-reload", dest="reload", action="store_false")
    parser.set_defaults(reload=True)
    args = parser.parse_args()

    main(port=args.port, reload=args.reload)


if __name__ == "__main__":
    cli()
