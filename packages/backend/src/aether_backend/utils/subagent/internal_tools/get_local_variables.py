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
    service = ctx.context.service
    return service.get_local_variables(function_name=function_name)
