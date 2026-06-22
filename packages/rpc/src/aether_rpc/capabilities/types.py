from dataclasses import dataclass
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


class XrefEntry(TypedDict):
    """A single cross-reference, as produced by ``collect_xrefs``."""

    from_address: str
    type: str
    is_code: bool
    from_name: str | None
    from_function: FunctionInfo | None


class PointerInfo(TypedDict):
    """Pointer value and the symbol it resolves to, if any."""

    value: str
    name: str | None


class AddressData(TypedDict):
    """Full context for a single address: bytes, semantics, and xrefs."""

    address: str
    name: str | None
    function: FunctionInfo | None
    item_size: int
    raw_bytes: str
    is_code: bool
    is_data: bool
    disassembly: str | None
    string: str | None
    pointer: PointerInfo | None
    xrefs_to: list[XrefEntry]
    xrefs_from: list[XrefEntry]


class XrefsResult(TypedDict):
    """Result of an xref query against a target address or symbol."""

    target_address: str
    target_name: str | None
    count: int
    xrefs: list[XrefEntry]


@dataclass
class Result:
    success: bool
    result: str

    def __str__(self) -> str:
        status = "Success" if self.success else "Failure"
        return f"[{status}] {self.result}"
