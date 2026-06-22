import ida_funcs
import idautils

from ..base import Capability
from ..types import Result


class ListFunctions(Capability):
    """Lists all functions present in the binary."""

    @property
    def name(self) -> str:
        return "list_functions"

    def execute(self) -> Result:
        """Return the name and address of every function in the binary.

        Runs on the main thread via execute_sync since IDA API calls
        are not safe to invoke from background threads.

        Returns:
            Result whose payload is a newline-separated list of function
            names and addresses.
        """
        functions = [
            f"{ida_funcs.get_func_name(ea)} {hex(ea)}" for ea in idautils.Functions()
        ]

        self.logger.info(f"{len(functions)} functions found")
        return Result(success=True, result="\n".join(functions))
