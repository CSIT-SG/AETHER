import ida_typeinf

INVALID_TYPE_ADDR = 18446744073709551615


def get_struct_id_by_name(struct_name: str) -> int | None:
    """Retrieves the struct ID associated with the specified struct name.

    Args:
        struct_name: The name of the type to look up.

    Returns:
        A Result object whose ``result`` attribute contains the corresponding
        struct ID.
    """

    struct_id = ida_typeinf.get_named_type_tid(struct_name)
    if struct_id == INVALID_TYPE_ADDR:
        return None
    return int(struct_id)
