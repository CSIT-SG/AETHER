from typing import NamedTuple, TypedDict


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


class FunctionPseudocode(TypedDict):
    """Decompiled pseudocode for a function."""

    name: str
    start_address: str
    pseudocode: str


class LocalVar(TypedDict):
    name: str
    type: str
    is_arg_var: bool
    is_stk_var: bool
    is_reg_var: bool


class RenameFuncResult(TypedDict):
    address: str
    new_name: str


class RenameLocalVarResult(TypedDict):
    function_address: str
    old_var_name: str
    new_var_name: str


class SetCommentResult(TypedDict):
    address: str
    comment: str


class FuncNameAddr(TypedDict):
    function_name: str
    address: str
    size: int
    is_lib: bool
    is_thunk: bool


class ListFunctionResult(TypedDict):
    count: int
    functions: list[FuncNameAddr]


class TakeSnapshotResult(TypedDict):
    snapshot_path: str


class FunctionTreeNode(TypedDict):
    function_name: str
    address: str
    children: list["FunctionTreeNode"]


class FunctionTreeResult(TypedDict):
    count: int
    root: FunctionTreeNode


class RenameStructFieldResult(TypedDict):
    struct_id: int
    struct_name: str
    old_field_name: str
    new_field_name: str


class ChangeStructFieldSizeResult(TypedDict):
    struct_id: int
    struct_name: str
    field_name: str
    new_size: str


class StructFieldResult(TypedDict):
    struct_id: int
    struct_name: str
    field_name: str


class StructResult(TypedDict):
    struct_id: int
    struct_name: str


class StructField(NamedTuple):
    name: str
    type: str
    array_size: int | None = None


class StructFieldWithOffset(NamedTuple):
    name: str
    type: str
    size: int
    offset: int


class StructInfo(NamedTuple):
    struct_id: str
    struct_name: str
    struct_fields: int


class RenameStructResult(TypedDict):
    struct_id: int
    old_struct_name: str
    new_struct_name: str


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
