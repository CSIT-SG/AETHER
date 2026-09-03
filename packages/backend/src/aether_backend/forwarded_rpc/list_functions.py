from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import ListFunctionResult


async def list_functions(service: AnyService) -> Result[ListFunctionResult]:
    """List the name and address of every function defined in the binary.

    Returns:
        Ok[ListFunctionResult]: A structured object containing:
            - count (int): The total number of functions found.
            - functions (list[FuncNameAddr]): The collected functions, each
              with:
                - function_name (str): The function's name (user-defined or
                  IDA auto-generated, e.g. "sub_140001000").
                - address (str): The function's start address as a hex
                  string, e.g. "0x140001000".
                - size (int): The size of the function in bytes.
                - is_lib (bool): True if the function is marked as a library
                    function in IDA, False otherwise.
                - is_thunk (bool): True if the function is marked as a thunk
                    function in IDA, False otherwise.
        Err[str]: An error message string if function enumeration fails
            (e.g. due to an unexpected database error).

    Examples:
        list_functions()
    """

    return service.list_functions()
