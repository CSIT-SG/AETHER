from pathlib import Path

from fastmcp.server.providers import FileSystemProvider

app_provider = FileSystemProvider(Path(__file__).parent / "features")
