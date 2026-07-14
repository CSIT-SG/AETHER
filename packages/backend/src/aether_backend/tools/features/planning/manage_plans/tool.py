from pathlib import Path
from typing import Annotated

from aether_backend.tools.features.planning.utils import PlanCrudAction, PlanStatus
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .create import create_plan_cb
from .delete import delete_plan_cb
from .list import list_plans_cb
from .read import read_plan_cb
from .update import update_plan_cb

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Manage Plans", destructiveHint=True),
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def manage_plans(
    action: Annotated[PlanCrudAction, "The action to perform on the plan."],
    plan_id: Annotated[
        str | None,
        "The ID of the plan to perform the action on. Required for read, update, and delete actions.",
    ] = None,
    title: Annotated[
        str | None, "The title of the plan. Required for create and optional for update."
    ] = None,
    description: Annotated[
        str | None, "The description of the plan. Optional for create and update."
    ] = None,
    status: Annotated[
        PlanStatus | None, "The status of the plan. Optional for create and update."
    ] = None,
) -> Program:
    """Create, read, update, delete, or list plans."""
    match action:
        case PlanCrudAction.CREATE:
            if title is None:
                raise ValueError("title is required for create")
            async for effect in create_plan_cb(title=title, description=description, status=status):
                yield effect
        case PlanCrudAction.READ:
            if plan_id is None:
                raise ValueError("plan_id is required for read")
            async for effect in read_plan_cb(plan_id=plan_id):
                yield effect
        case PlanCrudAction.UPDATE:
            if plan_id is None:
                raise ValueError("plan_id is required for update")
            async for effect in update_plan_cb(
                plan_id=plan_id,
                title=title,
                description=description,
                status=status,
            ):
                yield effect
        case PlanCrudAction.DELETE:
            if plan_id is None:
                raise ValueError("plan_id is required for delete")
            async for effect in delete_plan_cb(plan_id=plan_id):
                yield effect
        case PlanCrudAction.LIST:
            async for effect in list_plans_cb(status=status):
                yield effect
        case _:
            raise ValueError(f"Unsupported plan action: {action!r}")
