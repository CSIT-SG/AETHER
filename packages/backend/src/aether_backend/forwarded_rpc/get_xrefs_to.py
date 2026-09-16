from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import XrefsResult


async def get_xrefs_to(
    service: AnyService, *, location: str | int, variable: str | None = None
) -> Result[XrefsResult]:
    """Find all locations that reference the given address or symbol name.

    Args:
        location (str | int): The target to look up cross-references for.
            Accepts a hex address string (e.g. "0x140001000"), a plain
            symbol name (e.g. "assign_buffer"), an IDA auto-generated name
            (e.g. "sub_DEADBEEF"), or an integer effective address.
        variable (str | None): The decompiler (Hex-Rays pseudocode) name of
            a local variable (e.g. "v4", "a1", or a renamed local) inside
            the function identified by `location` — not the raw stack
            frame/assembly name (e.g. "var_10"). When it resolves to a
            stack frame member, the
            result's `stack_info` field is populated with that member's
            own cross-references; this does not change what `location` is
            resolved against or what the top-level `xrefs` contains. If
            `variable` can't be resolved to a stack variable, `stack_info`
            is simply `None` and the call still succeeds.

    Returns:
        Ok[XrefsResult]: A structured object containing:
            - target_address (str): The resolved hex address of `location`,
              e.g. "0x140001000".
            - target_name (str | None): The symbolic name at that address,
              or None if no name is defined there.
            - count (int): The number of cross-references found for
              `location` itself.
            - xrefs (list): The collected cross-reference entries pointing
              to `location`.
            - stack_info (dict | None): When `variable` resolves to a
              stack frame member, its name, frame offsets, and its own
              `xrefs` list; otherwise None.
        Err[str]: An error message string in the following cases:
            - The location could not be resolved to a valid effective
              address.
            - An exception was raised while collecting cross-references
              (e.g. an invalid or corrupted address).

    Examples:
        get_xrefs_to("assign_buffer")
        get_xrefs_to("0x140001000")
        get_xrefs_to("sub_DEADBEEF")
        get_xrefs_to("assign_buffer", variable="v4")
    """

    return service.get_xrefs_to(location=location, variable=variable)
