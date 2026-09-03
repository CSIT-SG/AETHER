from typing import TypedDict


class FunctionInfo(TypedDict):
    """Brief identifying info for a function (name + entry point)."""

    name: str
    start_address: str


class FunctionMetadata(TypedDict):
    """Full metadata for a function."""

    name: str
    start_address: str
    end_address: str
    size_bytes: int
    flags: str


class FunctionPseudocode(TypedDict):
    """Decompiled pseudocode for a function."""

    name: str
    start_address: str
    pseudocode: str


class RenameFuncResult(TypedDict):
    address: str
    new_name: str


class FuncNameAddr(TypedDict):
    function_name: str
    address: str
    size: int
    is_lib: bool
    is_thunk: bool


class ListFunctionResult(TypedDict):
    count: int
    functions: list[FuncNameAddr]


class FunctionTreeNode(TypedDict):
    function_name: str
    address: str
    children: list["FunctionTreeNode"]


class FunctionTreeResult(TypedDict):
    count: int
    root: FunctionTreeNode
