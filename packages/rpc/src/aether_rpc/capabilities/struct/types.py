from typing import NamedTuple, TypedDict


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


class ChangeStructFieldTypeResult(TypedDict):
    struct_id: int
    struct_name: str
    field_name: str
    new_type: str


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
    array_length: int | None = None


class StructFieldWithOffset(NamedTuple):
    name: str
    type: str
    size: int
    offset: int


class StructInfo(TypedDict):
    struct_id: int
    struct_name: str
    applied_to: list[str]
    struct_fields: list[StructFieldWithOffset]


class AllStructs(TypedDict):
    number_of_structs: int
    structs: list[StructInfo]


class AppliedStruct(TypedDict):
    function_name: str
    struct_id: int
    struct_name: str
    variable: str
    address: str


class StructAtAddress(TypedDict):
    address: str
    struct_id: int
    struct_name: str


class RenameStructResult(TypedDict):
    struct_id: int
    old_struct_name: str
    new_struct_name: str
