from typing import TypedDict

from aether_rpc.capabilities.function.types import FunctionInfo
from aether_rpc.capabilities.variables.types import XrefEntry


class PointerInfo(TypedDict):
    """Pointer value and the symbol it resolves to, if any."""

    value: str
    name: str | None


class AddressData(TypedDict):
    """Full context for a single address: bytes, semantics, and xrefs."""

    address: str
    name: str | None
    type: str
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


class TakeSnapshotResult(TypedDict):
    snapshot_path: str


class SectionInfo(TypedDict):
    name: str
    start: str  # hex address
    end: str  # hex address
    size: int
    perms: str  # e.g. "RWX"


class BinaryMetadataResult(TypedDict):
    file_name: str
    file_path: str
    file_size: int
    sha256: str
    md5: str
    crc32: str
    architecture: str
    bitness: int
    file_type: str
    entry_point: str  # hex address
    image_base: str  # hex address
    section_count: int
    sections: list[SectionInfo]
