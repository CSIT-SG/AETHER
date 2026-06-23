from __future__ import annotations

from typing import Any, Protocol

from ..logging_utils import get_chatbot_logger


logger = get_chatbot_logger("chatbot.bridge")


class ChatbotBackendBridge(Protocol):
    def resolve_function(self, function_name: str) -> Any | None:
        ...

    def get_function_name(self, function_ref: Any) -> str:
        ...

    def list_functions(self) -> list[dict[str, str]]:
        ...

    def get_function_pseudocode(self, function_name: str) -> str | None:
        ...

    def get_data_at_address(self, location: str, count: int = 16) -> dict[str, Any] | None:
        ...

    def get_xrefs_to(self, location: str) -> list[dict[str, Any]] | None:
        ...

    def annotate_function(self, advice: str = "") -> str:
        ...

    def generate_python_script(self, func_name: str, objective: str) -> str:
        ...

    def list_structs(self) -> list[str]:
        ...

    def get_struct_definition(self, struct_name: str) -> dict[str, Any] | None:
        ...

    def create_struct(self, struct_name: str, size: int = 0) -> str:
        ...

    def add_struct_field(self, struct_name: str, field_name: str, field_type: str, offset: int) -> str:
        ...

    def update_struct_field(
        self,
        struct_name: str,
        field_name: str,
        new_field_name: str | None = None,
        new_field_type: str | None = None,
        new_offset: int | None = None,
    ) -> str:
        ...

    def remove_struct_field(self, struct_name: str, field_name: str | None = None, offset: int | None = None) -> str:
        ...

    def apply_struct_to_variable_or_address(
        self,
        struct_name: str,
        function_name: str | None = None,
        variable_name: str | None = None,
        address: str | None = None,
    ) -> str:
        ...

    def rename_struct(self, old_name: str, new_name: str) -> str:
        ...

    def set_struct_size(self, struct_name: str, size: int) -> str:
        ...


class NullChatbotBackendBridge:
    def resolve_function(self, function_name: str) -> Any | None:
        return None

    def get_function_name(self, function_ref: Any) -> str:
        return str(function_ref)

    def list_functions(self) -> list[dict[str, str]]:
        return []

    def get_function_pseudocode(self, function_name: str) -> str | None:
        return None

    def get_data_at_address(self, location: str, count: int = 16) -> dict[str, Any] | None:
        return None

    def get_xrefs_to(self, location: str) -> list[dict[str, Any]] | None:
        return None

    def annotate_function(self, advice: str = "") -> str:
        return "IDA backend is unavailable; cannot annotate function."

    def generate_python_script(self, func_name: str, objective: str) -> str:
        return "IDA backend is unavailable; cannot generate a Python script."

    def list_structs(self) -> list[str]:
        return []

    def get_struct_definition(self, struct_name: str) -> dict[str, Any] | None:
        return None

    def create_struct(self, struct_name: str, size: int = 0) -> str:
        return "IDA backend is unavailable; cannot create struct."

    def add_struct_field(self, struct_name: str, field_name: str, field_type: str, offset: int) -> str:
        return "IDA backend is unavailable; cannot add struct field."

    def update_struct_field(
        self,
        struct_name: str,
        field_name: str,
        new_field_name: str | None = None,
        new_field_type: str | None = None,
        new_offset: int | None = None,
    ) -> str:
        return "IDA backend is unavailable; cannot update struct field."

    def remove_struct_field(self, struct_name: str, field_name: str | None = None, offset: int | None = None) -> str:
        return "IDA backend is unavailable; cannot remove struct field."

    def apply_struct_to_variable_or_address(
        self,
        struct_name: str,
        function_name: str | None = None,
        variable_name: str | None = None,
        address: str | None = None,
    ) -> str:
        return "IDA backend is unavailable; cannot apply struct."

    def rename_struct(self, old_name: str, new_name: str) -> str:
        return "IDA backend is unavailable; cannot rename struct."

    def set_struct_size(self, struct_name: str, size: int) -> str:
        return "IDA backend is unavailable; cannot resize struct."


def create_default_chatbot_bridge() -> ChatbotBackendBridge:
    try:
        import ida_kernwin  # noqa: F401
    except Exception:
        return NullChatbotBackendBridge()
    return IDAChatbotBackendBridge()


class IDAChatbotBackendBridge:
    def resolve_function(self, function_name: str) -> int | None:
        import ida_idaapi
        import ida_kernwin
        import ida_name

        result = {"ea": ida_idaapi.BADADDR}

        def _resolve_sync():
            result["ea"] = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return None
        ida_kernwin.execute_sync(_resolve_sync, ida_kernwin.MFF_READ)
        if result["ea"] == ida_idaapi.BADADDR:
            return None
        return int(result["ea"])

    def get_function_name(self, function_ref: Any) -> str:
        import ida_funcs

        try:
            name = ida_funcs.get_func_name(int(function_ref))
            return name or f"0x{int(function_ref):X}"
        except Exception:
            return str(function_ref)

    def list_functions(self, pattern: str = "", limit: int = 500) -> list[dict[str, str]]:
        import ida_funcs
        import ida_kernwin
        import idautils
        import re

        functions: list[dict[str, str]] = []
        
        try:
            regex = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error:
            regex = None

        def _list_functions_sync():
            for func_ea in idautils.Functions():
                name = ida_funcs.get_func_name(func_ea)
                if not name:
                    continue
                if regex and not regex.search(name):
                    continue
                functions.append({"name": name, "address": hex(func_ea)})
                if len(functions) >= limit:
                    break
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return None
        ida_kernwin.execute_sync(_list_functions_sync, ida_kernwin.MFF_READ)
        return functions

    def get_function_pseudocode(self, function_name: str) -> str | None:
        import ida_hexrays
        import ida_idaapi
        import ida_kernwin
        import ida_name

        from ...utils import refresh_functions

        result: dict[str, str | None] = {"code": None}

        def _get_pseudocode_sync():
            func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
            if func_ea == ida_idaapi.BADADDR:
                return False
            try:
                refresh_functions(
                    fallback_func_addr=int(func_ea),
                    log_prefix="[AETHER] [Chatbot]",
                )
            except Exception:
                pass
            try:
                result["code"] = str(ida_hexrays.decompile(func_ea))
                return True
            except ida_hexrays.DecompilationFailure:
                result["code"] = f"// Decompilation failed for {function_name}"
                return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return None
        ida_kernwin.execute_sync(_get_pseudocode_sync, ida_kernwin.MFF_READ)
        return result["code"]

    def get_data_at_address(self, location: str, count: int = 16) -> dict[str, Any] | None:
        import ida_bytes
        import ida_funcs
        import ida_idaapi
        import ida_kernwin
        import ida_name
        import idautils
        import idc

        data: dict[str, Any] = {
            "ea": None,
            "name": None,
            "symbol_hints": "none",
            "segment": None,
            "item_kind": "unknown",
            "item_head": None,
            "item_end": None,
            "item_size": 0,
            "function_context": "outside_function",
            "bytes": "No bytes found",
            "string": "No string found",
            "disasm": None,
            "pointer_candidate": None,
            "pointer_target": None,
            "repeat_pattern": None,
            "xrefs_to_total": 0,
            "xrefs_to": [],
            "warnings": [],
        }

        def _resolve_location_to_ea(value: str) -> int:
            if value is None:
                return ida_idaapi.BADADDR
            try:
                return int(str(value), 16)
            except (ValueError, TypeError):
                try:
                    return ida_name.get_name_ea(ida_idaapi.BADADDR, str(value))
                except Exception:
                    return ida_idaapi.BADADDR

        def _name_or_address(ea: int) -> str:
            try:
                name = ida_name.get_name(ea) or idc.get_name(ea)
                return name if name else f"0x{ea:X}"
            except Exception:
                return f"0x{ea:X}"

        def _symbol_hints(name: str) -> str:
            if not name:
                return "none"
            hints = []
            if name.startswith("sub_"):
                hints.append("auto_function")
            if name.startswith("unk_"):
                hints.append("unknown_symbol")
            if name.startswith("off_"):
                hints.append("offset_symbol")
            if name.startswith(("byte_", "word_", "dword_", "qword_")):
                hints.append("typed_data_symbol")
            if name.startswith("asc_"):
                hints.append("string_like_symbol")
            return ", ".join(hints) if hints else "none"

        def _function_context(ea: int) -> dict[str, Any]:
            ctx: dict[str, Any] = {
                "in_function": False,
                "is_function_start": False,
                "function_name": None,
                "function_start": None,
                "offset": None,
            }
            try:
                func = ida_funcs.get_func(ea)
                if not func:
                    return ctx
                func_name = ida_funcs.get_func_name(func.start_ea) or f"0x{func.start_ea:X}"
                ctx["in_function"] = True
                ctx["is_function_start"] = ea == func.start_ea
                ctx["function_name"] = func_name
                ctx["function_start"] = func.start_ea
                ctx["offset"] = ea - func.start_ea
            except Exception:
                return ctx
            return ctx

        def _format_function_context(ctx: dict[str, Any]) -> str:
            if not ctx.get("in_function"):
                return "outside_function"
            if ctx.get("is_function_start"):
                return f"function_start:{ctx.get('function_name')}"
            return f"in_function:{ctx.get('function_name')}+0x{ctx.get('offset', 0):X}"

        def _xref_type_to_text(xref_type: int) -> str:
            if xref_type == 1:
                return "Data_Offset"
            if xref_type == 2:
                return "Data_Write"
            if xref_type == 3:
                return "Data_Read"
            if xref_type in [16, 17]:
                return "Code_Call"
            if xref_type == 21:
                return "Code_Jump"
            return "Unknown"

        def _get_data_sync():
            try:
                ea = _resolve_location_to_ea(location)
                if ea == ida_idaapi.BADADDR:
                    return False

                data["ea"] = hex(ea)
                data["name"] = _name_or_address(ea)
                data["symbol_hints"] = _symbol_hints(data["name"])
                data["segment"] = idc.get_segm_name(ea) or "unknown"

                flags = idc.get_full_flags(ea)
                if idc.is_code(flags):
                    data["item_kind"] = "code"
                elif idc.is_data(flags):
                    data["item_kind"] = "data"
                elif idc.is_unknown(flags):
                    data["item_kind"] = "unknown"

                item_head = idc.get_item_head(ea)
                item_end = idc.get_item_end(ea)
                data["item_head"] = hex(item_head) if item_head != ida_idaapi.BADADDR else None
                data["item_end"] = hex(item_end) if item_end != ida_idaapi.BADADDR else None
                if item_head != ida_idaapi.BADADDR and item_end != ida_idaapi.BADADDR and item_end >= item_head:
                    data["item_size"] = item_end - item_head

                data["function_context"] = _format_function_context(_function_context(ea))
                data["disasm"] = idc.generate_disasm_line(ea, 0)

                num = max(1, min(int(count), 1024))
                try:
                    raw_bytes = ida_bytes.get_bytes(ea, num)
                    if raw_bytes:
                        data["bytes"] = raw_bytes.hex()
                        ptr_size = 8 if getattr(idc, "__EA64__", False) else 4
                        if len(raw_bytes) >= ptr_size:
                            ptr_val = int.from_bytes(raw_bytes[:ptr_size], byteorder="little", signed=False)
                            data["pointer_candidate"] = f"0x{ptr_val:X}"
                            if ida_bytes.is_loaded(ptr_val):
                                data["pointer_target"] = _name_or_address(ptr_val)

                        first_byte = ida_bytes.get_byte(ea)
                        if first_byte >= 0:
                            max_scan = 0x1000
                            run_len = 1
                            while run_len < max_scan:
                                if ida_bytes.get_byte(ea + run_len) != first_byte:
                                    break
                                run_len += 1
                            if run_len > 1:
                                data["repeat_pattern"] = {
                                    "byte": f"0x{first_byte:02X}",
                                    "length": run_len,
                                    "end_ea": hex(ea + run_len - 1),
                                    "scan_truncated": run_len == max_scan,
                                }
                except Exception as exc:
                    data["bytes"] = f"Error reading bytes: {exc}"

                try:
                    string_value = idc.get_strlit_contents(ea)
                    if string_value:
                        data["string"] = string_value.decode("utf-8", errors="replace")
                except Exception as exc:
                    data["string"] = f"Error decoding: {exc}"

                preview = []
                total_xrefs = 0
                try:
                    for xref in idautils.XrefsTo(ea):
                        total_xrefs += 1
                        if len(preview) < 10:
                            preview.append(
                                {
                                    "from": hex(xref.frm),
                                    "name": _name_or_address(xref.frm),
                                    "type": _xref_type_to_text(xref.type),
                                    "from_context": _format_function_context(_function_context(xref.frm)),
                                }
                            )
                except Exception as exc:
                    data["warnings"].append(f"xref scan failed: {exc}")
                data["xrefs_to_total"] = total_xrefs
                data["xrefs_to"] = preview
                return True
            except Exception as exc:
                data["warnings"].append(f"unexpected data collection error: {exc}")
                return bool(data["ea"])

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return None
        ida_kernwin.execute_sync(_get_data_sync, ida_kernwin.MFF_READ)
        return data if data["ea"] else None

    def get_xrefs_to(self, location: str) -> list[dict[str, Any]] | None:
        import ida_funcs
        import ida_idaapi
        import ida_kernwin
        import ida_name
        import idautils
        import idc

        xrefs: list[dict[str, Any]] = []
        target: dict[str, Any] = {
            "ea": None,
            "name": None,
            "symbol_hints": "none",
            "context": "outside_function",
            "warnings": [],
        }

        def _resolve_location_to_ea(value: str) -> int:
            try:
                return int(str(value), 16)
            except (ValueError, TypeError):
                try:
                    return ida_name.get_name_ea(ida_idaapi.BADADDR, str(value))
                except Exception:
                    return ida_idaapi.BADADDR

        def _name_or_address(ea: int) -> str:
            try:
                name = ida_name.get_name(ea) or idc.get_name(ea)
                return name if name else f"0x{ea:X}"
            except Exception:
                return f"0x{ea:X}"

        def _symbol_hints(name: str) -> str:
            if not name:
                return "none"
            hints = []
            if name.startswith("sub_"):
                hints.append("auto_function")
            if name.startswith("unk_"):
                hints.append("unknown_symbol")
            if name.startswith("off_"):
                hints.append("offset_symbol")
            if name.startswith(("byte_", "word_", "dword_", "qword_")):
                hints.append("typed_data_symbol")
            if name.startswith("asc_"):
                hints.append("string_like_symbol")
            return ", ".join(hints) if hints else "none"

        def _function_context(ea: int) -> dict[str, Any]:
            ctx: dict[str, Any] = {"in_function": False, "is_function_start": False, "function_name": None, "offset": None}
            try:
                func = ida_funcs.get_func(ea)
                if not func:
                    return ctx
                ctx["in_function"] = True
                ctx["is_function_start"] = ea == func.start_ea
                ctx["function_name"] = ida_funcs.get_func_name(func.start_ea) or f"0x{func.start_ea:X}"
                ctx["offset"] = ea - func.start_ea
            except Exception:
                return ctx
            return ctx

        def _format_function_context(ctx: dict[str, Any]) -> str:
            if not ctx.get("in_function"):
                return "outside_function"
            if ctx.get("is_function_start"):
                return f"function_start:{ctx.get('function_name')}"
            return f"in_function:{ctx.get('function_name')}+0x{ctx.get('offset', 0):X}"

        def _xref_type_to_text(xref_type: int) -> str:
            if xref_type == 1:
                return "Data_Offset"
            if xref_type == 2:
                return "Data_Write"
            if xref_type == 3:
                return "Data_Read"
            if xref_type in [16, 17]:
                return "Code_Call"
            if xref_type == 21:
                return "Code_Jump"
            return "Unknown"

        def _get_xrefs_sync():
            try:
                ea = _resolve_location_to_ea(location)
                if ea == ida_idaapi.BADADDR:
                    target["warnings"].append("target could not be resolved")
                    return False
                target_name = _name_or_address(ea)
                target["ea"] = hex(ea)
                target["name"] = target_name
                target["symbol_hints"] = _symbol_hints(target_name)
                target["context"] = _format_function_context(_function_context(ea))

                for xref in idautils.XrefsTo(ea):
                    caller_ctx = _function_context(xref.frm)
                    xrefs.append(
                        {
                            "from": hex(xref.frm),
                            "name": _name_or_address(xref.frm),
                            "type": _xref_type_to_text(xref.type),
                            "from_context": _format_function_context(caller_ctx),
                            "from_is_function_start": bool(caller_ctx.get("is_function_start")),
                        }
                    )
                return True
            except Exception as exc:
                target["warnings"].append(f"xref scan failed: {exc}")
                return False

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return None
        ida_kernwin.execute_sync(_get_xrefs_sync, ida_kernwin.MFF_READ)
        if not target["ea"]:
            return None
        return [{"target": target, **xref} for xref in xrefs] or [{"target": target}]

    def annotate_function(self, advice: str = "") -> str:
        from ... import add_analysis_entry, load_config, validate_basic_config
        from ...async_manager import schedule_ui_task
        from ...realtime.realtime import run_custom_prompt_analysis, run_fast_look_analysis
        from ...utils import prepare_activate_context, refresh_functions

        advice = (advice or "").strip()

        def _update_annotation_config(config):
            config["SINGLE_ANALYSIS_MODEL"] = config.get("SINGLE_ANALYSIS_MODEL") or config.get("OPENAI_MODEL")
            config["rename_filter_enabled"] = True

        config, current_func_addr, current_func_name = prepare_activate_context(
            load_config,
            validate_basic_config,
            _update_annotation_config,
        )
        if not config:
            return "Failed to start annotation: invalid config or no function at cursor."

        async def _chatbot_annotation_thread():
            try:
                if advice:
                    success = await run_custom_prompt_analysis(config, current_func_name, current_func_addr, advice)
                    if not success:
                        return "Custom annotation failed."
                    refresh_functions(fallback_func_addr=current_func_addr, log_prefix="[AETHER] [Chatbot]")
                    return f"Successfully ran custom annotation for '{current_func_name}' at {current_func_addr} with advice: {advice}"
                else:
                    success, gatherer_out, annotator_out, structured_commands = await run_fast_look_analysis(
                        config,
                        current_func_name,
                        current_func_addr,
                    )
                    if not success:
                        return "Fast look annotation failed."
                    add_analysis_entry(
                        gatherer_output=gatherer_out,
                        annotator_output=annotator_out,
                        starting_function=current_func_name,
                        structured_data=structured_commands,
                    )
                    refresh_functions(fallback_func_addr=current_func_addr, log_prefix="[AETHER] [Chatbot]")
                    return f"Successfully ran fastlook annotation for '{current_func_name}' at {current_func_addr}."
            except Exception as exc:
                return f"Error during annotation: {exc}"

        task = schedule_ui_task(_chatbot_annotation_thread())
        if task is None:
            return "Failed to queue annotation task."

        try:
            return task.result(timeout=300)  # 5 minute timeout
        except Exception as exc:
            return f"Error or timeout waiting for annotation: {exc}"

    def generate_python_script(self, func_name: str, objective: str) -> str:
        import ida_kernwin
        import traceback

        try:
            from ..chatbot_pygen.python_script_generation import DeobfuscateHandler

            print(f"[GENERATE_PYTHON_SCRIPT] Generating script for {func_name}")
            print(f"[GENERATE_PYTHON_SCRIPT] Objective: {objective}")
            
            # Use a list to store result from the inner function
            exec_result = ["Error: execute_sync failed to run."]

            def _run_gen():
                try:
                    exec_result[0] = DeobfuscateHandler.generate_script_and_window(
                        user_prompt=objective or "",
                        target_func_name=func_name,
                        is_chatbot_tool_call=True,
                    )
                except Exception as inner_e:
                    msg = f"Error in DeobfuscateHandler: {inner_e}"
                    print(f"[GENERATE_PYTHON_SCRIPT] {msg}")
                    traceback.print_exc()
                    exec_result[0] = msg

            from ainalyse.qt_shim import QtWidgets
            app = QtWidgets.QApplication.instance()
            if app is None or app.closingDown():
                return "Error: IDA is shutting down."
            ida_kernwin.execute_sync(_run_gen, ida_kernwin.MFF_WRITE)
            return exec_result[0]
        except Exception as e:
            msg = f"Outer Error: {e}"
            print(f"[GENERATE_PYTHON_SCRIPT] {msg}")
            traceback.print_exc()
            return f"Error: {str(e)}"

    def list_structs(self) -> list[str]:
        import idautils
        import ida_kernwin
        import ida_typeinf

        names: list[str] = []

        def _sync() -> bool:
            # Prefer idautils.Structs() listing because it reflects current IDB
            # structs and works in environments where ida_struct is unavailable 
            # (e.g. IDA 9.0+, where ida_struct was officially removed).
            try:
                structs = list(idautils.Structs())
                logger.info("list_structs idautils count=%s", len(structs))
                for _, _, name in structs:
                    if name:
                        names.append(name)
            except Exception:
                # Fall back to TIL scan if idautils path fails
                logger.exception("list_structs idautils enumeration failed, falling back to TIL")
                pass

            if names:
                logger.info("list_structs returning via idautils names_count=%s", len(names))
                return True

            til = ida_typeinf.get_idati()
            get_qty = getattr(ida_typeinf, "get_ordinal_qty", None)
            if get_qty is None:
                logger.warning("list_structs fallback unavailable: ida_typeinf.get_ordinal_qty missing")
                return True
            qty = get_qty(til)
            logger.info("list_structs fallback TIL ordinal_qty=%s", qty)
            for ordinal in range(1, qty + 1):
                tif = ida_typeinf.tinfo_t()
                if not tif.get_numbered_type(til, ordinal) or not tif.is_udt():
                    continue
                type_name = ""
                try:
                    type_name = ida_typeinf.idc_get_type_name(ordinal) or ""
                except Exception:
                    type_name = ""
                if not type_name:
                    try:
                        type_name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
                    except Exception:
                        type_name = ""
                if type_name:
                    names.append(type_name)
            logger.info("list_structs returning via TIL names_count=%s", len(names))
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return None
        ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_READ)
        return sorted(set(names))

    def get_struct_definition(self, struct_name: str) -> dict[str, Any] | None:
        import ida_kernwin
        import ida_typeinf

        from ...struct_creator.tools import get_struct_definition

        result: dict[str, Any] = {"struct_name": struct_name, "size": 0, "fields": []}

        def _sync() -> bool:
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(ida_typeinf.get_idati(), struct_name):
                size = tif.get_size()
                if isinstance(size, int) and size >= 0:
                    result["size"] = int(size)
            _, fields = get_struct_definition(struct_name)
            if fields is None:
                return False
            result["fields"] = [
                {"field_type": field_type, "field_name": field_name, "offset": int(offset)}
                for field_type, field_name, offset in fields
            ]
            return True

        ok = ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_READ)
        return result if ok else None

    def create_struct(self, struct_name: str, size: int = 0) -> str:
        import ida_kernwin
        import ida_typeinf

        result = {"message": ""}

        def _sync() -> bool:
            til = ida_typeinf.get_idati()
            existing = ida_typeinf.tinfo_t()
            if existing.get_named_type(til, struct_name):
                result["message"] = f"Struct '{struct_name}' already exists."
                return True

            udt = ida_typeinf.udt_type_data_t()
            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            if size > 0:
                udt.total_size = int(size)
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE)
            result["message"] = f"Struct '{struct_name}' created."
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return "Error: IDA is shutting down."
        ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_WRITE)
        return result["message"] or f"Struct '{struct_name}' processed."

    def add_struct_field(self, struct_name: str, field_name: str, field_type: str, offset: int) -> str:
        import ida_kernwin

        from ...struct_creator.tools import declare_c_struct

        failed = {"fields": []}

        def _sync() -> bool:
            failed["fields"] = declare_c_struct(struct_name, [(field_name, field_type, int(offset))])
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return "Error: IDA is shutting down."
        ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_WRITE)
        if failed["fields"]:
            return f"Failed to add field '{field_name}' to '{struct_name}': {failed['fields']}"
        return f"Added/updated field '{field_name}' in '{struct_name}' at offset 0x{int(offset):X}."

    def update_struct_field(
        self,
        struct_name: str,
        field_name: str,
        new_field_name: str | None = None,
        new_field_type: str | None = None,
        new_offset: int | None = None,
    ) -> str:
        definition = self.get_struct_definition(struct_name)
        if not definition:
            return f"Struct '{struct_name}' not found."
        match = None
        for field in definition.get("fields", []):
            if field.get("field_name") == field_name:
                match = field
                break
        if not match:
            return f"Field '{field_name}' not found in '{struct_name}'."

        return self.add_struct_field(
            struct_name,
            new_field_name or str(match.get("field_name") or field_name),
            new_field_type or str(match.get("field_type") or "uint8_t"),
            int(new_offset if new_offset is not None else match.get("offset", 0)),
        )

    def remove_struct_field(self, struct_name: str, field_name: str | None = None, offset: int | None = None) -> str:
        definition = self.get_struct_definition(struct_name)
        if not definition:
            return f"Struct '{struct_name}' not found."

        kept: list[tuple[str, str, int]] = []
        removed = 0
        for field in definition.get("fields", []):
            same_name = field_name is not None and field.get("field_name") == field_name
            same_offset = offset is not None and int(field.get("offset", -1)) == int(offset)
            if same_name or same_offset:
                removed += 1
                continue
            kept.append((str(field.get("field_name")), str(field.get("field_type")), int(field.get("offset", 0))))

        if removed == 0:
            return f"No matching field found in '{struct_name}'."

        import ida_kernwin

        from ...struct_creator.tools import declare_c_struct

        def _sync() -> bool:
            declare_c_struct(struct_name, kept)
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return "Error: IDA is shutting down."
        ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_WRITE)
        return f"Removed {removed} field(s) from '{struct_name}'."

    def apply_struct_to_variable_or_address(
        self,
        struct_name: str,
        function_name: str | None = None,
        variable_name: str | None = None,
        address: str | None = None,
    ) -> str:
        import ida_bytes
        import ida_funcs
        import ida_hexrays
        import ida_idaapi
        import ida_kernwin
        import ida_name
        import ida_nalt
        import ida_typeinf

        def _is_pointer_type(tif: ida_typeinf.tinfo_t | None) -> bool:
            if tif is None:
                return False
            try:
                return bool(tif.is_ptr())
            except Exception:
                return False

        if function_name and variable_name:
            from ...struct_creator.tools import set_variable_type

            result = {"ok": False, "target_type": f"{struct_name}*", "error": ""}

            def _sync_local() -> bool:
                func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
                func = ida_funcs.get_func(func_ea)
                if not func:
                    result["error"] = f"Function '{function_name}' not found."
                    return True

                current_is_pointer = True
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        lvars = cfunc.get_lvars()
                        target_lvar = next((v for v in lvars if v.name == variable_name), None)
                        if target_lvar is not None:
                            tif = None
                            attr = getattr(target_lvar, "type", None)
                            if callable(attr):
                                tif = attr()
                            elif attr is not None:
                                tif = attr
                            if tif is None:
                                attr = getattr(target_lvar, "tif", None)
                                if callable(attr):
                                    tif = attr()
                                elif attr is not None:
                                    tif = attr
                            current_is_pointer = _is_pointer_type(tif)
                        else:
                            global_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, variable_name)
                            if global_ea != ida_idaapi.BADADDR and not ida_funcs.get_func(global_ea):
                                global_tif = ida_typeinf.tinfo_t()
                                if ida_nalt.get_tinfo(global_tif, global_ea):
                                    current_is_pointer = _is_pointer_type(global_tif)
                except Exception:
                    pass

                result["target_type"] = f"{struct_name}*" if current_is_pointer else struct_name
                result["ok"] = bool(set_variable_type(function_name, variable_name, result["target_type"]))
                return True

            from ainalyse.qt_shim import QtWidgets
            app = QtWidgets.QApplication.instance()
            if app is None or app.closingDown():
                return "Error: IDA is shutting down."
            ida_kernwin.execute_sync(_sync_local, ida_kernwin.MFF_WRITE)
            if result["ok"]:
                return (
                    f"Applied type '{result['target_type']}' to variable '{variable_name}' in '{function_name}'."
                )
            if result["error"]:
                return result["error"]
            return (
                f"Failed to apply '{result['target_type']}' to variable '{variable_name}' in '{function_name}'."
            )

        if address:
            result = {"ok": False, "target_type": struct_name}

            def _sync_addr() -> bool:
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, address)
                if ea == ida_idaapi.BADADDR:
                    try:
                        ea = int(address, 16)
                    except Exception:
                        return False

                base_tif = ida_typeinf.tinfo_t()
                if not base_tif.get_named_type(ida_typeinf.get_idati(), struct_name):
                    return False

                current_tif = ida_typeinf.tinfo_t()
                current_is_pointer = bool(ida_nalt.get_tinfo(current_tif, ea) and _is_pointer_type(current_tif))
                apply_tif = base_tif
                if current_is_pointer:
                    ptr_tif = ida_typeinf.tinfo_t()
                    if not ptr_tif.create_ptr(base_tif):
                        return False
                    apply_tif = ptr_tif
                    result["target_type"] = f"{struct_name}*"
                else:
                    result["target_type"] = struct_name

                result["ok"] = bool(ida_typeinf.apply_tinfo(ea, apply_tif, ida_typeinf.TINFO_DEFINITE))
                return True

            from ainalyse.qt_shim import QtWidgets
            app = QtWidgets.QApplication.instance()
            if app is None or app.closingDown():
                return "Error: IDA is shutting down."
            ida_kernwin.execute_sync(_sync_addr, ida_kernwin.MFF_WRITE)
            if result["ok"]:
                return f"Applied type '{result['target_type']}' at address '{address}'."
            return f"Failed to apply type '{result['target_type']}' at address '{address}'."

        return "Error: provide either (function_name + variable_name) or address."

    def rename_struct(self, old_name: str, new_name: str) -> str:
        import ida_kernwin
        import ida_typeinf

        old_name = (old_name or "").strip()
        new_name = (new_name or "").strip()
        if not old_name or not new_name:
            return "Error: old_name and new_name are required."

        result = {"message": ""}

        def _sync() -> bool:
            til = ida_typeinf.get_idati()
            src = ida_typeinf.tinfo_t()
            if not src.get_named_type(til, old_name):
                result["message"] = f"Struct '{old_name}' not found."
                return True

            existing = ida_typeinf.tinfo_t()
            if existing.get_named_type(til, new_name):
                result["message"] = f"Struct '{new_name}' already exists."
                return True

            set_result = src.set_named_type(
                til,
                new_name,
                ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE,
            )
            if set_result != 0:
                result["message"] = f"Renamed struct '{old_name}' to '{new_name}'."
            else:
                result["message"] = f"Failed to rename struct '{old_name}' to '{new_name}'."
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return "Error: IDA is shutting down."
        ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_WRITE)
        return result["message"]

    def set_struct_size(self, struct_name: str, size: int) -> str:
        import ida_kernwin
        import ida_typeinf

        struct_name = (struct_name or "").strip()
        if not struct_name:
            return "Error: struct_name is required."
        if size < 0:
            return "Error: size cannot be negative."

        result = {"message": ""}

        def _sync() -> bool:
            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(til, struct_name):
                result["message"] = f"Struct '{struct_name}' not found."
                return True
            if not tif.is_udt():
                result["message"] = f"Type '{struct_name}' is not a struct."
                return True

            udt_data = ida_typeinf.udt_type_data_t()
            tif.get_udt_details(udt_data)
            udt_data.total_size = int(size)
            udt_data.taudt_bits |= ida_typeinf.TAUDT_FIXED
            if not tif.create_udt(udt_data, ida_typeinf.BTF_STRUCT):
                result["message"] = f"Failed to update struct size for '{struct_name}'."
                return True
            set_result = tif.set_named_type(
                til,
                struct_name,
                ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE,
            )
            if set_result != 0:
                result["message"] = f"Set size of '{struct_name}' to {int(size)} bytes (0x{int(size):X})."
            else:
                result["message"] = f"Failed to save resized struct '{struct_name}'."
            return True

        from ainalyse.qt_shim import QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return "Error: IDA is shutting down."
        ida_kernwin.execute_sync(_sync, ida_kernwin.MFF_WRITE)
        return result["message"]
