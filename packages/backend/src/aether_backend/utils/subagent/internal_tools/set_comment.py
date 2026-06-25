from typing import cast

from aether_backend.utils.subagent.constants import SubagentTool
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def set_comment(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, comment: str
) -> bool:
    service = ctx.context.service
    return cast(bool, service.set_comment(address=address, comment=comment))
