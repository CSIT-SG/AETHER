import ida_idaapi
import ida_typeinf


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


def get_struct(struct: str | int):
    """Retrieves the struct object either with either struct name or id.

    Args:
        struct: The name or id of the struct to retrieve.

    Returns:
        Whether get_struct succeeded, along with a list containing struct name, id, tif and udt.
    """
    if isinstance(struct, int):
        struct_id = struct
    else:
        struct_id = get_struct_id_by_name(str(struct))

    if struct_id is None:
        return False, f"Struct with the specified name {struct} does not exist."

    tif = ida_typeinf.tinfo_t()

    if not tif.get_type_by_tid(struct_id):
        return False, f"Struct with the specified id {struct_id} does not exist."

    if not tif.is_struct():
        return False, f"{struct} is not a struct."

    struct_name = str(tif.get_type_name())

    # Get UDT members.
    udt = ida_typeinf.udt_type_data_t()

    if not tif.get_udt_details(udt):
        return False, f"{struct_name} is not a structure."

    return True, [struct_name, struct_id, tif, udt]
