from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import FunctionTreeResult


async def get_functions_called_recursively(
    service: AnyService, *, address: str | int
) -> Result[FunctionTreeResult]:
    """Look up the function enclosing the given address and return its call tree.

    Args:
        address: Hex or decimal string address anywhere within the target function.

    Returns:
        A Result whose ``result`` holds the call tree rooted at the starting function,
        or an error message if the address is invalid or no function bounds it.
    """
    return service.get_functions_called_recursively(address=address)
