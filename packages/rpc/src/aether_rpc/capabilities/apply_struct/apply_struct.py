import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idaapi

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import AppliedStruct
from ..utils import get_struct, resolve_function_name


class ApplyStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "apply_struct"

    def get_function(self, function_name):
        ea = resolve_function_name(function_name)
        if ea is None:
            return Err(result=f"Symbol '{function_name}' not found")

        pfn = ida_funcs.get_func(ea)

        tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(tif, pfn):
            return Err(result=f"Unable to get info for Function {function_name}.")

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return Err(result=f"Unable to get member info for Function {function_name}.")

        return function_name, ea, pfn, tif, udt

    def handle_frame_offset(self, frame_offset, variable, func, struct):
        diff = 0x0 - ida_frame.calc_frame_offset(func["pfn"], 0x0)
        lvars_start = ida_frame.frame_off_lvars(func["pfn"])
        savregs_start = ida_frame.frame_off_savregs(func["pfn"])

        stack_offset = frame_offset + diff

        if not (
            lvars_start <= frame_offset and frame_offset <= savregs_start - struct["tif"].get_size()
        ):
            return Err(
                result=f"Struct {struct['name']} is too big to replace Variable {variable} in stack."
            )

        for member in func["udt"]:
            var_start = member.offset // 8
            var_end = member.offset // 8 + member.type.get_size()
            if not (
                var_end <= frame_offset or var_start >= frame_offset + struct["tif"].get_size()
            ):
                ida_frame.delete_frame_members(func["pfn"], var_start, var_end)

        if ida_frame.define_stkvar(func["pfn"], variable, stack_offset, struct["tif"]):
            ida_hexrays.mark_cfunc_dirty(func["ea"])
            return Ok(
                result=AppliedStruct(
                    function_name=func["name"],
                    struct_id=struct["id"],
                    struct_name=struct["name"],
                    variable=variable,
                    address=hex(func["ea"]),
                )
            )
        else:
            return Err(result=f"Failed to apply Struct {struct['name']} on Variable {variable}.")

    def execute(
        self,
        struct: str | int,
        function_name: str,
        variable: str,
    ) -> Result[AppliedStruct]:
        """Apply structure to a variable in a function.

        Args:
            struct: The name or id of the struct to apply.
            function_name: The function containing the target variable.
            variable: The name of the variable to apply struct to.

        Returns:
            A Result whose ``success`` reports whether the applying succeeded and
            If variable in stack:
            ``result`` carries the function name, the id and name of the struct
            applied and the variable the struct was applied to.
            If variable has address (statically allocated or heap):
            ``result`` carries the address, and the id and name of the struct
            applied,
        """
        status, output = get_struct(struct)
        struct = dict()
        if status:
            struct["name"], struct["id"], struct["tif"], _ = output
        else:
            return Err(result=output)

        output = self.get_function(function_name)
        func = dict()
        if isinstance(output, Err):
            return output
        func["name"], func["ea"], func["pfn"], func["tif"], func["udt"] = output

        cfunc = ida_hexrays.decompile(func["ea"])
        frame_offset = None
        lvars = dict()
        for lvar in cfunc.get_lvars():
            # Attempt to get pseudocode var first
            lvars[lvar.get_stkoff()] = lvar
            if variable != lvar.name:
                continue
            if not lvar.type().is_ptr():
                frame_offset = lvar.get_stkoff()
                break
            # Handle ptr
            new_tif = ida_typeinf.tinfo_t()
            new_tif.create_ptr(struct["tif"])

            info = ida_hexrays.lvar_saved_info_t()
            info.ll = lvar
            info.type = new_tif

            if ida_hexrays.modify_user_lvar_info(func["ea"], ida_hexrays.MLI_TYPE, info):
                ida_hexrays.mark_cfunc_dirty(func["ea"])
                return Ok(
                    result=AppliedStruct(
                        function_name=func["name"],
                        struct_id=struct["id"],
                        struct_name=struct["name"],
                        variable=variable,
                        address=hex(func["ea"]),
                    )
                )
            else:
                return Err(
                    result=f"Failed to apply Struct {struct['name']} on Variable {variable}."
                )

        if frame_offset:
            return self.handle_frame_offset(frame_offset, variable, func, struct)

        for member in func["udt"]:
            if not variable == member.name:
                continue
            frame_offset = member.offset // 8
            if frame_offset in lvars:
                if not lvars[frame_offset].type().is_ptr():
                    continue
                # Handle ptr
                new_tif = ida_typeinf.tinfo_t()
                new_tif.create_ptr(struct["tif"])

                if ida_frame.set_frame_member_type(func["pfn"], frame_offset, new_tif):
                    ida_hexrays.mark_cfunc_dirty(func["ea"])
                    return Ok(
                        result=AppliedStruct(
                            function_name=func["name"],
                            struct_id=struct["id"],
                            struct_name=struct["name"],
                            variable=variable,
                            address=hex(func["ea"]),
                        )
                    )
                else:
                    return Err(
                        result=f"Failed to apply Struct {struct['name']} on Variable {variable}."
                    )
            break

        if frame_offset:
            return self.handle_frame_offset(frame_offset, variable, func, struct)

        # Attempt to get static global var last
        address = ida_name.get_name_ea(idaapi.BADADDR, variable)
        if ida_typeinf.apply_tinfo(address, struct["tif"], ida_typeinf.TINFO_DEFINITE):
            ida_hexrays.mark_cfunc_dirty(func["ea"])
            return Ok(
                result=AppliedStruct(
                    function_name=func["name"],
                    struct_id=struct["id"],
                    struct_name=struct["name"],
                    variable=variable,
                    address=hex(address),
                )
            )
        else:
            return Err(result=f"Variable {variable} does not exist.")
