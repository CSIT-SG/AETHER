# type:ignore

import json
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from aether_backend.utils.get_rpc_service import AnyService
from aether_backend.utils.subagent import SubagentToolDependencies, build_subagent_tool
from agents import FunctionTool, RunContextWrapper


def make_ctx(service: AnyService | None = None) -> RunContextWrapper[SubagentToolDependencies]:
    """Build a RunContextWrapper around a SubagentToolDependencies instance."""
    deps: SubagentToolDependencies = SubagentToolDependencies(
        service=service if service is not None else MagicMock(spec=AnyService)
    )
    return RunContextWrapper(context=deps)


async def sample_tool(service: AnyService, *, arg1: int, arg2: str) -> dict[str, Any]:
    """A stand-in tool function shaped like get_data_at_address."""
    return {"arg1": arg1, "arg2": arg2}


async def failing_tool(service: AnyService, *, arg1: int, arg2: str) -> dict[str, Any]:
    """A stand-in tool function whose body raises, to test what happens downstream."""
    raise ValueError("boom")


@pytest.fixture
def built_tool() -> FunctionTool:
    return cast(FunctionTool, build_subagent_tool(sample_tool))


@pytest.fixture
def built_tool_failing() -> FunctionTool:
    return cast(FunctionTool, build_subagent_tool(failing_tool))


@pytest.mark.asyncio
async def test_missing_required_field_returns_error_string(built_tool: FunctionTool) -> None:
    ctx: RunContextWrapper[Any] = make_ctx()

    # arg2 is missing entirely -- this is the bug that used to crash the run.
    result: Any = await built_tool.on_invoke_tool(ctx, json.dumps({"arg1": 1}))

    assert isinstance(result, str)
    assert "arg2" in result
    assert built_tool.name in result


@pytest.mark.asyncio
async def test_wrong_type_returns_error_string(built_tool: FunctionTool) -> None:
    ctx: RunContextWrapper[SubagentToolDependencies] = make_ctx()

    result: Any = await built_tool.on_invoke_tool(
        ctx, json.dumps({"arg1": "not-an-int", "arg2": "x"})
    )

    assert isinstance(result, str)
    assert "arg1" in result


@pytest.mark.asyncio
async def test_malformed_json_syntax_returns_error_string(built_tool: FunctionTool) -> None:
    ctx: RunContextWrapper[SubagentToolDependencies] = make_ctx()

    # Trailing comma -> not valid JSON at all (json.JSONDecodeError path).
    malformed_json: str = '{"arg1": 1, "arg2": "x",}'
    result: Any = await built_tool.on_invoke_tool(ctx, malformed_json)

    assert isinstance(result, str)


@pytest.mark.asyncio
async def test_valid_args_still_calls_through(built_tool: FunctionTool) -> None:
    ctx: RunContextWrapper[SubagentToolDependencies] = make_ctx()

    result: dict[str, Any] = await built_tool.on_invoke_tool(
        ctx, json.dumps({"arg1": 1, "arg2": "x"})
    )

    assert result == {"arg1": 1, "arg2": "x"}


@pytest.mark.asyncio
async def test_service_dependency_is_passed_through() -> None:
    """
    The `service` dependency should be resolved from ctx.context and passed as
    the first positional arg to the wrapped function, unaffected by the
    validation try/except.
    """
    received: dict[str, Any] = {}

    async def capturing_tool(service: AnyService, *, arg1: int) -> None:
        received["service"] = service
        received["arg1"] = arg1

    tool: FunctionTool = build_subagent_tool(capturing_tool)
    fake_service: MagicMock = MagicMock(spec=AnyService)
    ctx: RunContextWrapper[SubagentToolDependencies] = make_ctx(service=fake_service)

    await tool.on_invoke_tool(ctx, json.dumps({"arg1": 1}))

    assert received["service"] is fake_service
    assert received["arg1"] == 1


@pytest.mark.asyncio
async def test_downstream_exception_still_propagates(built_tool_failing: FunctionTool) -> None:
    """
    Documents current behavior: only JSON/validation errors are caught.
    If `func` itself raises, that exception is NOT caught and propagates,
    since the try/except only wraps `model.model_validate_json(...)`.
    """
    ctx: RunContextWrapper[SubagentToolDependencies] = make_ctx()

    with pytest.raises(ValueError, match="boom"):
        await built_tool_failing.on_invoke_tool(ctx, json.dumps({"arg1": 1, "arg2": "x"}))
