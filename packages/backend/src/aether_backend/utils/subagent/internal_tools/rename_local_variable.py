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
            function_address: Hex or decimal string address inside or at the function start.
            old_var_name: Current name of the variable to rename.
            new_var_name: New name to assign.
    """
    service = ctx.context.service
    return service.rename_local_variable(
        function_address=function_address, old_var_name=old_var_name, new_var_name=new_var_name
    )
