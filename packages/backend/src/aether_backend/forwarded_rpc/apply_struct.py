from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import AppliedStruct


async def apply_struct(
    service: AnyService,
    *,
    struct: str | int,
    function_name: str,
    variable: str,
) -> Result[AppliedStruct]:
    """Apply structure to a variable in a function. Works for both local and global variables.

    Args:
        struct: The name or id of the struct to apply.
        function_name: The function containing the target variable.
        variable: The name of the variable to apply struct to.

    Returns:
        A Result whose ``success`` reports whether the applying succeeded and
        ``result`` carries the function name, the id and name of the struct
        applied, the variable the struct was applied to and its address.
    """
    return service.apply_struct(struct=struct, function_name=function_name, variable=variable)
