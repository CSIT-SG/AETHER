import ida_hexrays

from ..base import Capability
from ..utils import resolve_function_name


class GetLocalVariables(Capability):

    @property
    def name(self) ->str:
        return "get_local_variables"

    def execute(self, function_name: str)-> list[ida_hexrays.lvars_t]:
        """ List all local variables in the pesudocode"""
        lvar_ls: list[ida_hexrays.lvars_t] = []
        ea: int |None = resolve_function_name(function_name)
        cfunc: ida_hexrays.cfuncptr_t = ida_hexrays.decompile(ea)
        lvars: ida_hexrays.lvars_t = cfunc.get_lvars()
        for lvar in lvars:
            lvar_ls.append(lvar)
        return lvar_ls

