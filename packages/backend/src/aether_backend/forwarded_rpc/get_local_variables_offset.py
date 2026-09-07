from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import LocalVarOffset


async def get_local_variables_offset(
    service: AnyService, *, function_name: str
) -> Result[list[LocalVarOffset]]:
    """List all local variables in the decompiled pseudocode of a function and their offsets.

    Args:
        function_name (str): The name of the function to inspect.

    Returns:
        Ok[list[LocalVarOffset]]: A list of local variables, each containing:
            - name (str): The variable name as it appears in the pseudocode.
            - stack_offset (str): The variable's stack offset.
        Err[str]: An error message string in the following cases:
            - The symbol could not be resolved to a known address.
            - IDA Hex-Rays raised a DecompilationFailure during decompilation.
            - Decompilation succeeded but returned no result.

    Examples:
            get_local_variables("dynamic_buffer")
            get_local_variables("sub_DEADBEEF")
    """
    return service.get_local_variables_offset(function_name=function_name)
