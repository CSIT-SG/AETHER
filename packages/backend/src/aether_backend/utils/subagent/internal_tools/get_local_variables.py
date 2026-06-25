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
    """Get a list of all local variables in the pesudocode

    Args:
        function_name: The symbolic name of the target function.
    """
    service = ctx.context.service
    return service.get_local_variables(function_name=function_name)
