from dataclasses import dataclass
from typing import Any, cast

from agents import RunContextWrapper, function_tool

from ..constants import SubagentTool
from .tags import SubagentToolRegistry

registry = SubagentToolRegistry()


@dataclass
class ToolDependencies:
    service: Any


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def set_comment(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, comment: str
) -> bool:
    service = ctx.context.service
    return cast(bool, service.set_comment(address=address, comment=comment))


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


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def rename_function(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, new_name: str
) -> bool:
    service = ctx.context.service
    return cast(bool, service.rename_function(address=address, new_name=new_name))


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_function_pseudocode(
    ctx: RunContextWrapper[ToolDependencies], *, function_name: str
) -> dict[str, Any] | None:
    service = ctx.context.service
    return cast(dict[str, Any] | None, service.get_function_pseudocode(function_name=function_name))


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_local_variables(
    ctx: RunContextWrapper[ToolDependencies], *, function_name: str
) -> list[dict[str, Any]] | None:
    service = ctx.context.service
    return cast(
        list[dict[str, Any]] | None, service.get_local_variables(function_name=function_name)
    )


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_data_at_address(
    ctx: RunContextWrapper[ToolDependencies], *, location: str | int
) -> dict[str, Any] | None:
    service = ctx.context.service
    return cast(dict[str, Any] | None, service.get_data_at_address(location=location))
