from typing import TypedDict

from aether_rpc.capabilities.function.types import FunctionInfo
from aether_rpc.capabilities.variables.types import XrefEntry


class IDAContext(TypedDict):
    name: str
    pseudocode: str | None
    function: FunctionInfo | None
    disassembly: str | None
    is_code: bool
    is_data: bool
    xrefs_to: list[XrefEntry]
    xrefs_from: list[XrefEntry]
