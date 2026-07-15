from typing import TypedDict

from aether_rpc.capabilities.types import FunctionInfo, XrefEntry


class IDAContext(TypedDict):
    name: str
    pseudocode: str | None
    function: FunctionInfo | None
    disassembly: str | None
    is_code: bool
    is_data: bool
    xrefs_to: list[XrefEntry]
    xrefs_from: list[XrefEntry]
