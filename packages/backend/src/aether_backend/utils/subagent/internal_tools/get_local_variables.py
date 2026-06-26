from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import LocalVar
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_local_variables(
    ctx: RunContextWrapper[ToolDependencies], *, function_name: str
) -> Result[list[LocalVar]]:
    """List all local variables in the decompiled pseudocode of a function.

    Args:
        function_name (str): The name of the function to inspect.

    Returns:
        Ok[list[LocalVar]]: Local variables with name, type, location,
            is_arg_var, is_stk_var, and is_reg_var fields.
        Err[str]: If the symbol is not found, or decompilation fails.
    """
    service = ctx.context.service
    return service.get_local_variables(function_name=function_name)
