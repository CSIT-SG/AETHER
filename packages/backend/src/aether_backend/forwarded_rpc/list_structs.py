from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import AllStructs


async def list_structs(service: AnyService) -> Result[AllStructs]:
    """List structs.

    Returns:
        A Result whose ``success`` reports whether the get succeeded and
        whose ``result`` carries the name of all of the structs.
    """
    return service.list_structs()
