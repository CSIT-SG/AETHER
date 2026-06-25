from typing import cast

from aether_backend.utils.subagent.constants import SubagentTool
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def rename_local_variable(
    ctx: RunContextWrapper[ToolDependencies],
    *,
    function_address: str | int,
    old_var_name: str,
    new_var_name: str,
) -> bool:
    service = ctx.context.service
    return cast(
        bool,
        service.rename_local_variable(
            function_address=function_address, old_var_name=old_var_name, new_var_name=new_var_name
        ),
    )
