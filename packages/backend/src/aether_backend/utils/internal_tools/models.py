from typing import Any, Callable, Generic, TypeVar, TypedDict

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class ToolSchema(TypedDict):
    type: str
    name: str
    description: str
    parameters: dict[str, Any]


class InternalToolRegistryEntry(Generic[T]):
    def __init__(
        self,
        args: type[T],
        execute: Callable[..., Any],
    ):
        self.args = args
        self.execute = execute

    @property
    def schema(self) -> ToolSchema:
        return {
            "type": "function",
            "name": self.execute.__name__,
            "description": self.execute.__doc__ or "",
            "parameters": self.args.model_json_schema(),
        }
