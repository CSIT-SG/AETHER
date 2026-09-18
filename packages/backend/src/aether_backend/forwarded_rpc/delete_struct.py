from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import StructResult


async def delete_struct(service: AnyService, *, struct: str | int) -> Result[StructResult]:
    """Deletes the struct.

    Args:
        struct: The name or id of the struct containing field to be changed.

    Returns:
        A Result whose ``success`` reports whether the deletion succeeded and
        whose ``result`` carries the struct id and name.
    """
    return service.delete_struct(struct=struct)
