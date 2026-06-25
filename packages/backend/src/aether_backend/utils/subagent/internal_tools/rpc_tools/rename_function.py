from typing import cast

from aether_backend.utils.subagent.constants import SubagentTool
from agents import RunContextWrapper, function_tool

from .base import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def rename_function(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, new_name: str
) -> bool:
    service = ctx.context.service
    return cast(bool, service.rename_function(address=address, new_name=new_name))
