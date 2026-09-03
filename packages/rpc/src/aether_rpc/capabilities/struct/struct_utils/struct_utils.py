import ida_idaapi
import ida_typeinf
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.struct_utils.types import InternalStructInfo
from aether_rpc.capabilities.struct.types import StructFieldWithOffset


def get_struct_id_by_name(struct_name: str) -> int | None:
    """Retrieves the struct ID associated with the specified struct name.

    Args:
        struct_name: The name of the struct to look up.

    Returns:
        The corresponding struct ID.
    """

    struct_id = ida_typeinf.get_named_type_tid(struct_name)
    if struct_id == ida_idaapi.BADADDR:
        return None
    return int(struct_id)


def get_struct(struct: str | int) -> Result[InternalStructInfo]:
    """Retrieves the struct object either with either struct name or id.

    Args:
        struct: The name or id of the struct to retrieve.

    Returns:
        Whether get_struct succeeded, along with a list containing struct name, id, tif and udt.
    """
    struct_id = struct if isinstance(struct, int) else get_struct_id_by_name(str(struct))

    if struct_id is None:
        return Err(
            f"Struct with the specified name {struct} does not exist.",
        )
    tif = ida_typeinf.tinfo_t()

    if not tif.get_type_by_tid(struct_id):
        return Err(
            f"Struct with the specified id {struct_id} does not exist.",
        )

    if not tif.is_struct():
        return Err(
            f"{struct} is not a struct.",
        )

    struct_name = str(tif.get_type_name())

    # Get UDT members.
    udt = ida_typeinf.udt_type_data_t()

    if not tif.get_udt_details(udt):
        return Err(
            f"{struct_name} is not a structure.",
        )

    return Ok(InternalStructInfo(struct_id=struct_id, struct_name=struct_name, tif=tif, udt=udt))


def get_struct_fields(udt: ida_typeinf.udt_type_data_t) -> list[StructFieldWithOffset]:
    return [
        StructFieldWithOffset(
            name=member.name,
            type=member.type.dstr(),
            size=member.type.get_size(),
            offset=member.offset // 8,
        )
        for member in udt
    ]
