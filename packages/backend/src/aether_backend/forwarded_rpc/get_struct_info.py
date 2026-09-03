from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.struct.types import StructInfo


async def get_struct_info(service: AnyService, *, struct: str | int) -> Result[StructInfo]:
    """Get struct info.

    Args:
        struct: The name or id of the struct to obtain info on.

    Returns:
        A Result whose ``success`` reports whether the get succeeded and
        whose ``result`` carries info about the struct.
    """
    return service.get_struct_info(struct=struct)
