from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameFuncResult
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def rename_function(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, new_name: str
) -> Result[RenameFuncResult]:
    """Rename the function at the given address.

    Args:
        address (str | int): Hex or decimal address within the target function.
        new_name (str): The new name to assign to the function.

    Returns:
        Ok[RenameFuncResult]: Contains the function address and new name.
        Err[str]: If the address is invalid, no function is found, or the rename fails.

    Example:
        rename_function(0xDEADBEEF, "find_strlen")
    """
    service = ctx.context.service
    return service.rename_function(address=address, new_name=new_name)
