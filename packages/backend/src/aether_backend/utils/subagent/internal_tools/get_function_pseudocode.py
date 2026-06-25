from typing import Any, cast

from aether_backend.utils.subagent.constants import SubagentTool
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_function_pseudocode(
    ctx: RunContextWrapper[ToolDependencies], *, function_name: str
) -> dict[str, Any] | None:
    service = ctx.context.service
    return cast(dict[str, Any] | None, service.get_function_pseudocode(function_name=function_name))
