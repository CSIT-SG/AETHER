from .constants import SubagentTool
from .registry import subagent_tool_tag
from typing import Any, cast
from agents import function_tool


# setters
@function_tool
@subagent_tool_tag(SubagentTool.ANNOTATOR)
async def set_comment(service: Any, *, address: str | int, comment: str) -> bool:
    return cast(bool, service.set_comment(address=address, comment=comment))


@function_tool
@subagent_tool_tag(SubagentTool.ANNOTATOR)
async def rename_local_variable(
    service: Any, *, function_address: str | int, old_var_name: str, new_var_name: str
) -> bool:
    return cast(
        bool,
        service.rename_local_variable(
            function_address=function_address, old_var_name=old_var_name, new_var_name=new_var_name
        ),
    )


@function_tool
@subagent_tool_tag(SubagentTool.ANNOTATOR)
async def rename_function(service: Any, *, address: str | int, new_name: str) -> bool:
    return cast(bool, service.rename_function(address=address, new_name=new_name))


# getters


@function_tool
@subagent_tool_tag(SubagentTool.ANNOTATOR)
def get_function_pseudocode(service: Any, *, function_name: str) -> dict[str, Any] | None:
    return cast(dict[str, Any] | None, service.get_function_pseudocode(function_name=function_name))


@function_tool
@subagent_tool_tag(SubagentTool.ANNOTATOR)
def get_local_variables(service: Any, *, function_name: str) -> list[dict[str, Any]] | None:
    return cast(
        list[dict[str, Any]] | None, service.get_local_variables(function_name=function_name)
    )


@function_tool
@subagent_tool_tag(SubagentTool.ANNOTATOR)
def get_data_at_address(service: Any, *, location: str | int) -> dict[str, Any] | None:
    return cast(dict[str, Any] | None, service.get_data_at_address(location=location))
