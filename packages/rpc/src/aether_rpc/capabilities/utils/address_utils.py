def resolve_effective_address(address: str) -> int:
    """Resolve a hex or decimal string address to an integer EA.

    Args:
        address: Hex string (e.g. '0x401000') or decimal string address.

    Returns:
        Integer effective address.

    Raises:
        ValueError: If the address string cannot be parsed.
    """
    if isinstance(address, str) and address.startswith("0x"):
        return int(address, 16)
    return int(address)
