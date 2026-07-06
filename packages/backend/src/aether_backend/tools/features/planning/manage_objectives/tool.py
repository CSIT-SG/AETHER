from pathlib import Path

from aether_backend.tools.features.planning.utils import ObjectiveCrudAction, ObjectiveStatus
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .create import create_objective_cb
from .delete import delete_objective_cb
from .update import update_objective_cb

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Manage Objectives", destructiveHint=True),
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def manage_objectives(
    action: ObjectiveCrudAction,
    plan_id: str,
    objective_id: str | None = None,
    text: str | None = None,
    status: ObjectiveStatus | None = None,
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
