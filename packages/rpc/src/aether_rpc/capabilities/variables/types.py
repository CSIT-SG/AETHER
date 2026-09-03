from typing import TypedDict

from aether_rpc.capabilities.function.types import FunctionInfo


class XrefEntry(TypedDict):
    """A single cross-reference, as produced by ``collect_xrefs``."""

    from_address: str
    type: str
    is_code: bool
    from_name: str | None
    from_function: FunctionInfo | None


class XrefsResult(TypedDict):
    """Result of an xref query against a target address or symbol."""

    target_address: str
    target_name: str | None
    count: int
    xrefs: list[XrefEntry]


class LocalVar(TypedDict):
    name: str
    type: str
    is_arg_var: bool
    is_stk_var: bool
    is_reg_var: bool


class RenameLocalVarResult(TypedDict):
    function_address: str
    old_var_name: str
    new_var_name: str


class StackVariableInfo(TypedDict):
    caller_func_ea: int
    start_off: int
    end_off: int
