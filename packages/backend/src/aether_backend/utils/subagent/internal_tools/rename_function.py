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
            address: Hex or decimal string address within the target function.
            new_name: The new name to assign to the function.
    """
    service = ctx.context.service
    return service.rename_function(address=address, new_name=new_name)
