from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import FunctionTreeResult


async def get_functions_called_recursively(
    service: AnyService, *, address: str | int
) -> Result[FunctionTreeResult]:
    """Look up the function enclosing the given address and return its call tree.

    Recursively walks callees starting from the enclosing function, building
    a nested tree of every function it calls (directly or transitively).
    Functions matching common library/runtime helpers are excluded from the callee lists.
    Use get_function_pseudocode to get the full function contex

    Args:
        address (str | int): Hex address string (e.g. "0x140001000"),
            decimal address string, or integer effective address, pointing
            anywhere within the target function's bounds.

    Returns:
        Ok[FunctionTreeResult]: A structured object containing:
            - count (int): Total number of nodes in the tree, including the
              root function itself.
            - root (FunctionTreeNode): The root of the call tree, where each
              node contains:
                - function_name (str): The function's symbolic name.
                - address (str): The function's start address as a hex
                  string, e.g. "0x140001000".
                - children (list[FunctionTreeNode]): Nested callee nodes,
                  following the same structure.
        Err[str]: An error message string in the following cases:
            - The address could not be resolved to a valid effective address.
            - No function in the database contains the given address.

    Examples:
        get_functions_called_recursively("0x140001000")
        get_functions_called_recursively("sub_DEADBEEF")
    """
    return service.get_functions_called_recursively(address=address)
