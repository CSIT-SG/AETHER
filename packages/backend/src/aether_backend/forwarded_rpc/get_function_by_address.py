from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import FunctionMetadata


async def get_function_by_address(
    service: AnyService, address: str | int
) -> Result[FunctionMetadata]:
    """Look up the function enclosing the given address and return its metadata.

    Args:
        address: Hex or decimal string address anywhere within the target function.

    Returns:
        A Result whose ``result`` holds the FunctionMetadata (name, start/end
        address, size, flags) on success, or an error message if the address
        is invalid or no function bounds it.
    """
    return service.get_function_by_address(address=address)
