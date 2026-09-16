from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import StackVariableXrefsResult


async def get_stack_variable_xrefs(
    service: AnyService, *, function_location: str | int, local_variable_name: str
) -> Result[StackVariableXrefsResult]:
    """Find references to a local variable's backing stack frame member, plus
    references to the owning function.

    Args:
        function_location (str | int): The function owning the variable — hex
            address, symbol name, or effective address.
        local_variable_name (str): The variable's Hex-Rays pseudocode name
            ("v4", "a1", or a renamed local), not the frame name ("var_10").

    Returns:
        Ok[StackVariableXrefsResult]: target_address, target_name, count and
            xrefs for the function, plus stack_info — the frame member's name,
            byte offsets and its own xrefs, or None when the variable has no
            stack backing (still a success).
        Err[str]: `function_location` could not be resolved, or IDA raised
            while collecting xrefs.

    Examples:
        get_stack_variable_xrefs("assign_buffer", local_variable_name="v4")
    """

    return service.get_stack_variable_xrefs(
        function_location=function_location, local_variable_name=local_variable_name
    )
