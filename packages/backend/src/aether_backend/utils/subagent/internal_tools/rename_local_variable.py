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
        Ok[RenameLocalVarResult]: Contains the function address and both old and new variable names.
        Err[str]: If the address is invalid, decompilation fails, or the variable is not found.
    """
    service = ctx.context.service
    return service.rename_local_variable(
        function_address=function_address, old_var_name=old_var_name, new_var_name=new_var_name
    )
