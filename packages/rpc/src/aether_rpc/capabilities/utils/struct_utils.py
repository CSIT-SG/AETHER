import ida_idaapi
import ida_typeinf


def get_struct_id_by_name(struct_name: str) -> int | None:
    """Retrieves the struct ID associated with the specified struct name.

    Args:
        struct_name: The name of the type to look up.

    Returns:
        A Result object whose ``result`` attribute contains the corresponding
        struct ID.
    """

    struct_id = ida_typeinf.get_named_type_tid(struct_name)
    if struct_id == ida_idaapi.BADADDR:
        return None
    return int(struct_id)
