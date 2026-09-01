import ida_funcs
import idautils

from ...base import Capability
from ...result import Err, Ok, Result
from ...types import FuncNameAddr, ListFunctionResult


class ListFunctions(Capability):
    """Lists all functions present in the binary."""

    @property
    def name(self) -> str:
        return "list_functions"

    def execute(self) -> Result[ListFunctionResult]:
        """Return the name, address, size, and lib/thunk flags of every
        function in the binary.

        Returns:
            A Result whose ``result`` holds the list of functions (name,
            address, size, is_lib, is_thunk) and their count.
        """
        try:
            functions = []
            for ea in idautils.Functions():
                func = ida_funcs.get_func(ea)
                size = (func.end_ea - func.start_ea) if func else 0
                is_lib = bool(func and func.flags & ida_funcs.FUNC_LIB)
                is_thunk = bool(func and func.flags & ida_funcs.FUNC_THUNK)

                functions.append(
                    FuncNameAddr(
                        function_name=ida_funcs.get_func_name(ea),
                        address=hex(ea),
                        size=size,
                        is_lib=is_lib,
                        is_thunk=is_thunk,
                    )
                )
        except Exception as e:
            self.logger.exception("Failed to list functions: %s", e)
            return Err(result=f"Failed to list functions: {e}")

        self.logger.info(f"{len(functions)} functions found")
        return Ok(result=ListFunctionResult(count=len(functions), functions=functions))
