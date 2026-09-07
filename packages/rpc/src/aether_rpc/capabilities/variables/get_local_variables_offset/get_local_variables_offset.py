from typing import cast

import ida_frame
import ida_funcs
import ida_hexrays
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import LocalVarOffset
from aether_rpc.capabilities.utils import resolve_function_name


class GetLocalVariablesOffset(Capability):
    @property
    def name(self) -> str:
        return "get_local_variables_offset"

    def execute(self, function_name: str) -> Result[list[LocalVarOffset]]:
        """List all local variables in the pesudocode"""
        ea: int | None = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return Err(result=f"Symbol '{function_name}' not found")
        try:
            cfunc = cast(ida_hexrays.cfuncptr_t | None, ida_hexrays.decompile(ea))
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error(f"Failed to decompile {function_name}\n{e}")
            return Err(result=f"Failed to decompile {function_name}: {e}")

        if cfunc is None:
            self.logger.error("Decompilation returned no result for", function_name)
            return Err(result=f"Decompilation returned no result for {function_name}")
        pfn = ida_funcs.get_func(ea)
        diff = 0x0 - ida_frame.calc_frame_offset(pfn, 0x0)
        lvars: ida_hexrays.lvars_t = cfunc.get_lvars()
        lvar_ls: list[LocalVarOffset] = [
            {
                "name": lvar.name,
                "stack_offset": hex(lvar.get_stkoff() + diff),
            }
            for lvar in lvars
        ]
        return Ok(result=lvar_ls)
