import ida_hexrays


def decompile_or_none(ea: int):
    """Decompile the function at ea and return the cfunc object, or None on failure.

    Args:
        ea: Start address of the function to decompile.

    Returns:
        cfunc_t if decompilation succeeded, None otherwise.
    """
    try:
        return ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return None
