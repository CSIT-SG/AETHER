from aether_backend.forwarded_rpc.get_data_at_address import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameLocalVarResult


async def rename_local_variable(
    service: AnyService,
    *,
    function_address: str | int,
    old_var_name: str,
    new_var_name: str,
) -> Result[RenameLocalVarResult]:
    """Rename a local variable in the Hex-Rays decompiled view.

    Args:
        function_address (str | int): Hex or decimal address inside the target function.
        old_var_name (str): Current name of the variable to rename.
        new_var_name (str): New name to assign.

    Returns:
        Ok[RenameLocalVarResult]: A structured object containing:
            - function_address (str): The hex string of the function's start address.
            - old_var_name (str): The variable's previous name.
            - new_var_name (str): The variable's newly assigned name.
        Err[str]: An error message string in the following cases:
            - The address could not be resolved to a valid effective address.
            - No function exists at or containing the resolved address.
            - IDA Hex-Rays raised a DecompilationFailure during decompilation.
            - Decompilation succeeded but returned no result.
            - No local variable with the given name exists in the function.
            - The Hex-Rays rename API call failed.

    Example:
        rename_local_variable(0xDEADBEEF, "v1", "buffer")
    """
    return service.rename_local_variable(
        function_address=function_address, old_var_name=old_var_name, new_var_name=new_var_name
    )
