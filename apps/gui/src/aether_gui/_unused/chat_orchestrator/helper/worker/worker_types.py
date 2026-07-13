from typing import Any, Literal, TypedDict

from ..ida import IDAContext


class WorkerTask(TypedDict):
    user_prompt: str
    ida_context: IDAContext


class WorkerEvent(TypedDict, total=False):
    kind: Literal[
        "status",
        "tool_call",
        "tool_result",
        "error",
    ]
    message: str
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    error: str
