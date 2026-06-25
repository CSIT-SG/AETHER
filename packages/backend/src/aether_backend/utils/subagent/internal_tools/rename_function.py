from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameFuncResult
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@function_tool
@registry.tag(SubagentTool.ANNOTATOR)
async def rename_function(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, new_name: str
) -> Result[RenameFuncResult]:
    service = ctx.context.service
    return service.rename_function(address=address, new_name=new_name)
