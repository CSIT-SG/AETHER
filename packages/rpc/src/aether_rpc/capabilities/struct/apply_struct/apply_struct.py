from typing import Any

import ida_frame
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_typeinf
import idaapi
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.misc.utils import resolve_function_name
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.utils import InternalStructInfo, get_struct
from aether_rpc.capabilities.types import AppliedStruct


class ApplyStruct(Capability):
    @property
    def name(self) -> str:
        return "apply_struct"

    def handle_frame_offset(
        self,
        frame_offset: int,
        variable: str,
        func: dict[str, Any],
        struct: InternalStructInfo,
    ) -> Result[AppliedStruct]:

        diff = 0x0 - ida_frame.calc_frame_offset(func["pfn"], 0x0)
        lvars_start = ida_frame.frame_off_lvars(func["pfn"])
        savregs_start = ida_frame.frame_off_savregs(func["pfn"])

        stack_offset = frame_offset + diff

        if not (
            lvars_start <= frame_offset and frame_offset <= savregs_start - struct.tif.get_size()
        ):
            return Err(
                result=f"Struct {struct.struct_name} is too big to replace Variable {variable} in stack."
            )

        for member in func["udt"]:
            var_start = member.offset // 8
            var_end = member.offset // 8 + member.type.get_size()
            if not (var_end <= frame_offset or var_start >= frame_offset + struct.tif.get_size()):
                ida_frame.delete_frame_members(func["pfn"], var_start, var_end)

        if ida_frame.define_stkvar(func["pfn"], variable, stack_offset, struct.tif):
            ida_hexrays.mark_cfunc_dirty(func["ea"])
            return Ok(
                result=AppliedStruct(
                    function_name=func["name"],
                    struct_id=struct.struct_id,
                    struct_name=struct.struct_name,
                    variable=variable,
                    address=hex(func["ea"]),
                )
            )
        else:
            return Err(
                result=f"Failed to apply Struct {struct.struct_name} on Variable {variable}."
            )

    def handle_argument(
        self,
        lvar: ida_hexrays.lvar_t,
        func: dict[str, Any],
        struct: InternalStructInfo,
    ) -> Result[AppliedStruct]:

        info = ida_hexrays.lvar_saved_info_t()
        lvar_size = lvar.type().get_size()
        info.ll = lvar
        info.type = struct.tif
        success = ida_hexrays.modify_user_lvar_info(func["ea"], ida_hexrays.MLI_TYPE, info)
        ida_hexrays.mark_cfunc_dirty(func["ea"])
        cfunc = ida_hexrays.decompile(func["ea"])
        pseudocode = "\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())
        if f"&{lvar.name}" in pseudocode or lvar_size != struct.tif.get_size():
            new_tif = ida_typeinf.tinfo_t()
            new_tif.create_ptr(struct.tif)
            info = ida_hexrays.lvar_saved_info_t()
            info.ll = lvar
            info.type = new_tif
            success = ida_hexrays.modify_user_lvar_info(func["ea"], ida_hexrays.MLI_TYPE, info)

        if success:
            ida_hexrays.mark_cfunc_dirty(func["ea"])
            return Ok(
                result=AppliedStruct(
                    function_name=func["name"],
                    struct_id=struct.struct_id,
                    struct_name=struct.struct_name,
                    variable=lvar.name,
                    address=hex(func["ea"]),
                )
            )
        else:
            return Err(
                result=f"Failed to apply Struct {struct.struct_name} on Variable {lvar.name}."
            )

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
            ``result`` carries the function name, the id and name of the struct
            applied, the variable the struct was applied to and its address.
        """
        # Obtain struct info and populate struct dict
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result

        # Obtain function info and populate func dict

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

        func = {
            "name": function_name,
            "ea": ea,
            "pfn": pfn,
            "tif": tif,
            "udt": udt,
        }

        # Check if variable is pseudocode variable first
        cfunc = ida_hexrays.decompile(func["ea"])
        frame_offset = None
        lvars = {}
        for lvar in cfunc.get_lvars():
            lvars[lvar.get_stkoff()] = lvar
            if variable != lvar.name:
                continue
            if lvar.is_arg_var:
                return self.handle_argument(lvar, func, struct_info)
            if not lvar.type().is_ptr():
                frame_offset = lvar.get_stkoff()
                break

            # Handle variable being a ptr
            new_tif = ida_typeinf.tinfo_t()
            new_tif.create_ptr(struct_info.tif)
            info = ida_hexrays.lvar_saved_info_t()
            info.ll = lvar
            info.type = new_tif
            if ida_hexrays.modify_user_lvar_info(func["ea"], ida_hexrays.MLI_TYPE, info):
                ida_hexrays.mark_cfunc_dirty(func["ea"])
                return Ok(
                    result=AppliedStruct(
                        function_name=func["name"],
                        struct_id=struct_info.struct_id,
                        struct_name=struct_info.struct_name,
                        variable=variable,
                        address=hex(func["ea"]),
                    )
                )
            else:
                return Err(
                    result=f"Failed to apply Struct {struct_info.struct_name} on Variable {variable}."
                )

        if frame_offset:
            return self.handle_frame_offset(frame_offset, variable, func, struct_info)

        # Check if variable is stack variable second
        for member in func["udt"]:
            if variable != member.name:
                continue
            frame_offset = member.offset // 8
            if frame_offset in lvars:
                if not lvars[frame_offset].type().is_ptr():
                    continue
                # Handle variable being a ptr
                new_tif = ida_typeinf.tinfo_t()
                new_tif.create_ptr(struct_info.tif)

                if ida_frame.set_frame_member_type(func["pfn"], frame_offset, new_tif):
                    ida_hexrays.mark_cfunc_dirty(func["ea"])
                    return Ok(
                        result=AppliedStruct(
                            function_name=func["name"],
                            struct_id=struct_info.struct_id,
                            struct_name=struct_info.struct_name,
                            variable=variable,
                            address=hex(func["ea"]),
                        )
                    )
                else:
                    return Err(
                        result=f"Failed to apply Struct {struct_info.struct_name} on Variable {variable}."
                    )
            break

        if frame_offset:
            return self.handle_frame_offset(frame_offset, variable, func, struct_info)

        # Check if variable is global variable last
        address = ida_name.get_name_ea(idaapi.BADADDR, variable)
        if ida_typeinf.apply_tinfo(address, struct_info.tif, ida_typeinf.TINFO_DEFINITE):
            ida_hexrays.mark_cfunc_dirty(func["ea"])
            return Ok(
                result=AppliedStruct(
                    function_name=func["name"],
                    struct_id=struct_info.struct_id,
                    struct_name=struct_info.struct_name,
                    variable=variable,
                    address=hex(address),
                )
            )
        else:
            return Err(result=f"Variable {variable} does not exist.")
