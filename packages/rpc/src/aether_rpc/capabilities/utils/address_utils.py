"""Address-related utilities for capability modules."""
import ida_idaapi
import ida_kernwin
import ida_name


def resolve_effective_address(address: str | int) -> int | None:
    """Resolve a hex or decimal string address to an integer EA.

    Args:
        address: Hex string (e.g. '0x401000') or decimal string address.

    Returns:
        Integer effective address.

    Raises:
        ValueError: If the address string cannot be parsed.
    """

    if isinstance(address, int):
        return address

    else:
        ea = ida_kernwin.str2ea(address)
        if ea == ida_idaapi.BADADDR:
            return None

        return ea

def resolve_function_name(name: str) -> int | None:
    """Resolve the address of the function containing the given name.

    Args:
        name: Name of the function to look up.

    Returns:
        The address of the enclosing function, or None if no function bounds the name.
    """

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if ea == ida_idaapi.BADADDR:
        return None

    return ea
