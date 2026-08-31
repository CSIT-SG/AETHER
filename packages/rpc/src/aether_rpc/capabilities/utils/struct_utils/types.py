from typing import NamedTuple

import ida_typeinf


class InternalStructInfo(NamedTuple):
    struct_id: int
    struct_name: str
    tif: ida_typeinf.tinfo_t
    udt: ida_typeinf.udt_type_data_t
