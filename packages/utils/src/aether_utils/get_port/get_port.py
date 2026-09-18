import socket
from typing import cast


def get_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, 0))
        except OSError as e:
            raise RuntimeError(f"Could not bind to {host}:0 - {e}") from e

        _, port = sock.getsockname()
        return cast(int, port)
