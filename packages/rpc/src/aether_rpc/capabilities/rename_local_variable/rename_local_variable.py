import ida_funcs
import ida_hexrays
import ida_kernwin

from ..base import Capability
from ..utils import resolve_effective_address


class RenameLocalVariable(Capability):
    """Renames a local variable inside a decompiled function."""

    @property
    def name(self) -> str:
        return "rename_local_variable"

    def execute(self, function_address: str, old_var_name: str, new_var_name: str) -> bool:
        """Rename a local variable in the Hex-Rays decompiled view.

        Args:
            function_address: Hex or decimal string address inside or at the function start.
            old_var_name: Current name of the variable to rename.
            new_var_name: New name to assign.

        Returns:
            True if the rename succeeded, False otherwise.
        """
        ea = resolve_effective_address(function_address)

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return False

        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc is None:
            self.logger.error(f"Failed to decompile function at {hex(func.start_ea)}")
            return False

        target = next((v for v in cfunc.get_lvars() if v.name == old_var_name), None)
        if target is None:
            self.logger.error(f"Local variable '{old_var_name}' not found in {hex(func.start_ea)}")
            return False

        info = ida_hexrays.lvar_saved_info_t()
        info.ll.location = target.location
        info.ll.defea = target.defea
        info.type = target.type
        info.name = new_var_name

        if not ida_hexrays.modify_user_lvar_info(func.start_ea, ida_hexrays.MLI_NAME, info):
            self.logger.error(f"modify_user_lvar_info failed for '{old_var_name}'")
            return False

        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui:
            vdui.refresh_view(True)

        self.logger.info(f"Renamed '{old_var_name}' to '{new_var_name}' in {hex(func.start_ea)}")
        return True
