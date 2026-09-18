from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result


async def get_struct_id_by_name(service: AnyService, *, struct_name: str) -> Result[int]:
    """Retrieves the struct ID associated with the specified struct name.

    Args:
        struct_name: The name of the struct to look up.

    Returns:
        A Result object whose ``result`` attribute contains the corresponding
        struct ID.
    """
    return service.get_struct_id_by_name(struct_name=struct_name)
