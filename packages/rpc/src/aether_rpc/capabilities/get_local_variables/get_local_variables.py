from typing import cast

import ida_hexrays

from ..base import Capability
from ..types import LocalVar
from ..utils import resolve_function_name


class GetLocalVariables(Capability):
    @property
    def name(self) -> str:
        return "get_local_variables"

    def execute(self, function_name: str) -> list[LocalVar] | None:
        """List all local variables in the pesudocode"""
        ea: int | None = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return None
        try:
            cfunc = cast(ida_hexrays.cfuncptr_t | None, ida_hexrays.decompile(ea))
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error(f"Failed to decompile {function_name}\n{e}")
            return None

        if cfunc is None:
            self.logger.error("Decompilation returned no result for", function_name)
            return None

        lvars: ida_hexrays.lvars_t = cfunc.get_lvars()
        lvar_ls: list[LocalVar] = [
            {
                "name": lvar.name,
                "type": lvar.type(),
                "location": lvar.location,
                "is_arg_var": lvar.is_arg_var,
                "is_stk_var": lvar.is_stk_var(),
                "is_reg_var": lvar.is_reg_var(),
            }
            for lvar in lvars
        ]
        return lvar_ls
