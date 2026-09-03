from typing import Any

from aether_backend.forwarded_rpc import delete_struct
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import StructResult

from ..utils import get_var_type


async def perform_delete_struct(
    svc: Any, function_address: HexAddress, var_name: str
) -> StructResult:
    struct = await get_var_type(svc, function_address, var_name)
    deleted = await delete_struct(svc, struct=struct)
    if deleted.success is False:
        raise RuntimeError(f"failed to delete struct {struct}")
    return deleted.result
