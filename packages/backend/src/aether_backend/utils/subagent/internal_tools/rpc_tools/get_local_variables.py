from typing import Any, cast

from aether_backend.utils.subagent.constants import SubagentTool
from agents import RunContextWrapper, function_tool

from .base import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_local_variables(
    ctx: RunContextWrapper[ToolDependencies], *, function_name: str
) -> list[dict[str, Any]] | None:
    service = ctx.context.service
    return cast(
        list[dict[str, Any]] | None, service.get_local_variables(function_name=function_name)
    )
