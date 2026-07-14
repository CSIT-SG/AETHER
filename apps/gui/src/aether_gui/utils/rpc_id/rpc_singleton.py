import ida_nalt
from aether_utils.file_id import file_id
from aether_utils.logger import get_logger

_shared_rpc_id: str | None = None
logger = get_logger("RPC ID Singleton")


def get_rpc_id() -> str | None:
    global _shared_rpc_id
    if _shared_rpc_id is None:
        path = ida_nalt.get_input_file_path()
        if not path:
            logger.warning("No input file path available yet")
            return
        _shared_rpc_id = file_id(path)

    return _shared_rpc_id
