import ida_funcs
import idautils

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import ListFunctionResult


class ListFunctions(Capability):
    """Lists all functions present in the binary."""

    @property
    def name(self) -> str:
        return "list_functions"

    def execute(self) -> Result[ListFunctionResult]:
        """Return the name and address of every function in the binary.

        Runs on the main thread via execute_sync since IDA API calls
        are not safe to invoke from background threads.

        Returns:
            A Result whose ``result`` holds the list of functions (name and
            address) and their count.
        """
        try:
            functions = [
                f"{ida_funcs.get_func_name(ea)} {hex(ea)}" for ea in idautils.Functions()
            ]
        except Exception as e:
            self.logger.exception("Failed to list functions: %s", e)
            return Err(result=f"Failed to list functions: {e}")

        self.logger.info(f"{len(functions)} functions found")
        return Ok(result=ListFunctionResult(count=len(functions), functions=functions))
