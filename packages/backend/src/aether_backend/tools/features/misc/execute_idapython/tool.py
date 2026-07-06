from pathlib import Path
from typing import cast

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from aether_backend.utils.validation import validate_service
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .execute_idapython import exec_code

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Execute IDAPython", openWorldHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def execute_idapython(rpc_id: str, code: str, ctx: Context = CurrentContext()) -> Program:
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    async for effect in exec_code(await validate_service(registry, rpc_id), code):
        yield effect
