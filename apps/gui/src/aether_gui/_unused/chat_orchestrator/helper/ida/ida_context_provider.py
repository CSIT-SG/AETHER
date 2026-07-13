from __future__ import annotations

import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import idautils

from .ida_types import IDAContext


class IDAContextProvider:
    def get_context(self) -> IDAContext:
        current_ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(current_ea)

        # Debug string
        print(f"[IDAContextProvider] current_ea = {current_ea}")

        function_ea = None
        function_name = None
        pseudocode = None
        disassembly = None

        if func is not None:
            function_ea = func.start_ea
            function_name = ida_name.get_name(func.start_ea)
            pseudocode = self._get_pseudocode(func.start_ea)
            disassembly = self._get_disassembly(func.start_ea, func.end_ea)

        return {
            "current_ea": current_ea,
            "function_ea": function_ea,
            "function_name": function_name,
            "pseudocode": pseudocode,
            "disassembly": disassembly,
            "selected_text": self._get_selected_text(),
            "processor": ida_idp.get_idp_name(),
            "bits": 64 if ida_ida.inf_is_64bit() else 32,
            "input_file_path": ida_nalt.get_input_file_path(),
        }

    def _get_pseudocode(self, function_ea: int) -> str | None:
        if ida_hexrays is None:
            return

        if not ida_hexrays.init_hexrays_plugin():
            return None

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception:
            return None

        if cfunc is None:
            return None

        lines: list[str] = []

        for line in cfunc.get_pseudocode():
            # Remove IDA color tags
            clean_line = ida_lines.tag_remove(line.line)
            lines.append(clean_line)

        return "\n".join(lines)

    def _get_disassembly(self, start_ea: int, end_ea: int, max_lines: int = 200) -> str:
        lines: list[str] = []

        for i, ea in enumerate(idautils.Heads(start_ea, end_ea)):
            if i >= max_lines:
                lines.append("; ... truncated ...")
                break

            disasm = ida_lines.generate_disasm_line(ea, 0)
            if disasm:
                clean_disasm = ida_lines.tag_remove(disasm)
                lines.append(f"{ea:#x}: {clean_disasm}")

        return "\n".join(lines)

    def _get_selected_text(self) -> str | None:
        # IDA selection handling depends on widget
        # Include later
        return None
