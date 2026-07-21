from collections.abc import Awaitable, Callable
from dataclasses import fields as dc_fields
from typing import Any, get_type_hints

from agents import FunctionTool, RunContextWrapper
from agents.strict_schema import ensure_strict_json_schema
from pydantic import create_model

from .models import ToolDependencies

# dependency names, in order, as declared on ToolDependencies -- this makes
# build_tool's positional-arg check generic over ToolDependencies' fields
_DEP_FIELDS = dc_fields(ToolDependencies)
_DEP_NAMES = tuple(f.name for f in _DEP_FIELDS)
_DEP_TYPES = get_type_hints(ToolDependencies)


def build_subagent_tool(func: Callable[..., Awaitable[Any]]) -> FunctionTool:
    code = func.__code__
    hints = get_type_hints(func)

    # positional params of func must match ToolDependencies' fields exactly
    # (names, order, and count)
    positional_names = code.co_varnames[: code.co_argcount]
    if positional_names != _DEP_NAMES:
        raise TypeError(
            f"{func.__name__}: positional params {positional_names} must match "
            f"ToolDependencies fields {_DEP_NAMES}"
        )
    # optionally enforce annotation matches too, since get_type_hints resolves
    # string/forward-ref annotations to real types for comparison
    for name in _DEP_NAMES:
        if name in hints and hints[name] != _DEP_TYPES[name]:
            raise TypeError(
                f"{func.__name__}: param `{name}` annotated {hints[name]}, "
                f"expected {_DEP_TYPES[name]} per ToolDependencies"
            )

    # names of kwonly params (everything after the dependency args)
    names = code.co_varnames[code.co_argcount : code.co_argcount + code.co_kwonlyargcount]
    defaults = func.__kwdefaults__ or {}

    # (type, default) per param, for pydantic's create_model
    param_fields: dict[str, Any] = {n: (hints.get(n, Any), defaults.get(n, ...)) for n in names}
    model = create_model(func.__name__, **param_fields)

    # resolves all dependencies from ctx.context, validates args, calls through
    async def on_invoke_tool(ctx: RunContextWrapper[ToolDependencies], args_json: str) -> Any:
        parsed = model.model_validate_json(args_json)
        deps = (getattr(ctx.context, name) for name in _DEP_NAMES)
        return await func(*deps, **parsed.model_dump())

    return FunctionTool(
        name=func.__name__,
        description=func.__doc__ or "",
        params_json_schema=ensure_strict_json_schema(model.model_json_schema()),
        on_invoke_tool=on_invoke_tool,
    )
