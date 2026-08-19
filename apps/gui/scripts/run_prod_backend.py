import argparse

from aether_backend.server import app
from uvicorn import run


def main(host: str, port: int) -> None:
    run(app, host=host, port=port)


def cli() -> None:
    parser = argparse.ArgumentParser(description="Run the production backend server")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(host=args.host, port=args.port)


if __name__ == "__main__":
    cli()
