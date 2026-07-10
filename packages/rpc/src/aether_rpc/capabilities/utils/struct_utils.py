import ida_typeinf

INVALID_TYPE_ADDR = 18446744073709551615


def get_type_id_by_name(type_name: str) -> int | None:
    """Retrieves the type ID associated with the specified type name.

    Args:
        type_name: The name of the type to look up.

    Returns:
        A Result object whose ``result`` attribute contains the corresponding
        type ID.
    """

    type_id = ida_typeinf.get_named_type_tid(type_name)
    if type_id == INVALID_TYPE_ADDR:
        return None
    return int(type_id)
