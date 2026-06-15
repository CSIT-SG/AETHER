from pathlib import Path
from os import getpid

from pydantic import BaseModel
from aether_utils.logger import get_logger


class RPCRegistryEntry(BaseModel):
    id: str
    port: int | None
    pid: int


logger = get_logger("rpc_registry")

class RPCFileRegistry:
    def __init__(self, data_file: Path) -> None:
        self._data_file = data_file

    def register(self, *, instance_id: str, port: int | None) -> None:
        entry = RPCRegistryEntry(
            id=instance_id,
            port=port,
            pid=getpid(),
        )

        self._data_file.write_text(entry.model_dump_json())

    def deregister(self) -> None:
        self._data_file.unlink(missing_ok=True)

    @staticmethod
    def load(data_file: Path) -> RPCRegistryEntry | None:
        if not data_file.is_file():
            return None

        try:
            content = data_file.read_text()
            return RPCRegistryEntry.model_validate_json(content)
        except Exception:
            logger.exception("Failed to load RPC registry entry from %s", data_file)
            return None