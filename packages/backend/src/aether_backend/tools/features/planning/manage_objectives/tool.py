from pathlib import Path
from typing import Annotated

from aether_backend.tools.features.planning.utils import ObjectiveCrudAction, ObjectiveStatus
from aether_backend.utils.effect import Program, effectful
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .create import create_objective_cb
from .delete import delete_objective_cb
from .update import update_objective_cb

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    task=True,
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Manage Objectives", destructive_hint=True),
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def manage_objectives(
    action: Annotated[ObjectiveCrudAction, "The action to perform on the objective."],
    plan_id: Annotated[str, "The ID of the plan to which the objective belongs."],
    objective_id: Annotated[str | None, "The ID of the objective to update or delete."] = None,
    text: Annotated[
        str | None, "The text of the objective. Required for create and optional for update."
    ] = None,
    status: Annotated[
        ObjectiveStatus | None, "The status of the objective. Optional for create and update."
    ] = None,
) -> Program:
    """Create, update, or delete objectives within a plan."""
    match action:
        case ObjectiveCrudAction.CREATE:
            if text is None:
                raise ValueError("text is required for create")
            async for effect in create_objective_cb(plan_id=plan_id, text=text, status=status):
                yield effect
        case ObjectiveCrudAction.UPDATE:
            if objective_id is None:
                raise ValueError("objective_id is required for update")
            async for effect in update_objective_cb(
                plan_id=plan_id,
                objective_id=objective_id,
                text=text,
                status=status,
            ):
                yield effect
        case ObjectiveCrudAction.DELETE:
            if objective_id is None:
                raise ValueError("objective_id is required for delete")
            async for effect in delete_objective_cb(plan_id=plan_id, objective_id=objective_id):
                yield effect
        case _:
            raise ValueError(f"Unsupported objective action: {action!r}")
