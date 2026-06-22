from typing import cast

import ida_hexrays

from ..base import Capability
from ..types import Result
from ..utils import resolve_function_name


class GetLocalVariables(Capability):
    @property
    def name(self) -> str:
        return "get_local_variables"

    def execute(self, function_name: str) -> Result:
        """List all local variables in the pseudocode of a function.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            Result whose payload is a newline-separated list of local
            variables as ``<type> <name>``, or a failure message.
        """
        ea = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return Result(success=False, result=f"Symbol '{function_name}' not found")

        try:
            cfunc = cast(ida_hexrays.cfuncptr_t | None, ida_hexrays.decompile(ea))
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error(f"Failed to decompile {function_name}\n{e}")
            return Result(success=False, result=f"Failed to decompile {function_name}")

        if cfunc is None:
            self.logger.error(f"Decompilation returned no result for {function_name}")
            return Result(
                success=False, result=f"Decompilation returned no result for {function_name}"
            )

        lvars = cfunc.get_lvars()
        self.logger.info(f"{len(lvars)} local variables found in {function_name}")
        return Result(
            success=True, result="\n".join(f"{lvar.type()} {lvar.name}" for lvar in lvars)
        )
