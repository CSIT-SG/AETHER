from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameLocalVarResult
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def rename_local_variable(
    ctx: RunContextWrapper[ToolDependencies],
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
    service = ctx.context.service
    return service.rename_local_variable(
        function_address=function_address, old_var_name=old_var_name, new_var_name=new_var_name
    )
