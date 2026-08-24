from dataclasses import dataclass
from enum import StrEnum

# REMOVE IF NEEDED. THIS IS IMPLEMENTED BEFORE MERGING TIMS BRANCH


# class StructOperation(StrEnum):
#     CREATE = "create"
#     UPDATE_NAME = "rename"
#     GET = "get"
#     DELETE = "delete"
#     ADD_FIELDS = "add_fields"


class StructFieldOperation(StrEnum):
    UPDATE_NAME = "rename"
    UPDATE_SIZE = "update_size"
    UPDATE_TYPE = "update_type"
    DELETE = "delete"


@dataclass
class StructField:
    name: str
    type: str
    size_bits: int  # or bytes?


class StructOperation(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
