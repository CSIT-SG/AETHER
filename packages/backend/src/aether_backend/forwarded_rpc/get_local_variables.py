from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import LocalVar


async def get_local_variables(service: AnyService, *, function_name: str) -> Result[list[LocalVar]]:
    """List all local variables in the decompiled pseudocode of a function.

    Args:
        function_name (str): The name of the function to inspect.

    Returns:
        Ok[list[LocalVar]]: A list of local variables, each containing:
            - name (str): The variable name as it appears in the pseudocode.
            - type (str): The variable's type as a string, e.g. "int *" or "DWORD".
            - location (str): The variable's storage location, e.g. a register or stack offset.
            - is_arg_var (bool): Whether the variable is a function argument.
            - is_stk_var (bool): Whether the variable is stack-allocated.
            - is_reg_var (bool): Whether the variable is stored in a register.
        Err[str]: An error message string in the following cases:
            - The symbol could not be resolved to a known address.
            - IDA Hex-Rays raised a DecompilationFailure during decompilation.
            - Decompilation succeeded but returned no result.

    Examples:
            get_local_variables("dynamic_buffer")
            get_local_variables("sub_DEADBEEF")
    """
    return service.get_local_variables(function_name=function_name)
