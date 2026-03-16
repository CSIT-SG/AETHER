import ida_funcs
import ida_hexrays
import ida_kernwin
import idaapi

from .. import add_analysis_entry

from ainalyse import load_config, validate_basic_config
from ainalyse.async_manager import use_async_worker, start_pipeline

from .dialog import CustomPromptDialog
from .realtime import run_custom_prompt_analysis, run_fast_look_analysis

class FastLookHandler(ida_kernwin.action_handler_t):
    is_running = False
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if FastLookHandler.is_running:
            print("[AETHER] [Fast Look] Fast look analysis is already running...")
            return 1
        
        try:
            config = load_config()
            
            # Use basic validation first
            is_valid, error_msg = validate_basic_config(config)
            if not is_valid:
                ida_kernwin.warning(error_msg)
                return 1
            
            config = load_config()
            config["SINGLE_ANALYSIS_MODEL"] = config.get("SINGLE_ANALYSIS_MODEL") or config.get("OPENAI_MODEL")
            config["rename_filter_enabled"] = True

            # GET ALL IDA INFORMATION ON MAIN THREAD BEFORE STARTING BACKGROUND THREAD
            try:
                ea = ida_kernwin.get_screen_ea()
                func = idaapi.get_func(ea)
                if not func:
                    ida_kernwin.warning("No function found at current location.")
                    return 1
                
                current_func_addr = hex(func.start_ea)
                current_func_name = ida_funcs.get_func_name(func.start_ea)
            except Exception as e:
                ida_kernwin.warning(f"Unable to get current function information: {e}")
                return 1
            
            print("[AETHER] [Fast Look] Generating fast look results...")

            @use_async_worker("FastLook")
            async def fast_look_thread(config, current_func_name, current_func_addr):
                try:
                    success, gatherer_out, annotator_out, structured_commands = await run_fast_look_analysis(config, current_func_name, current_func_addr)
                    if not success:
                        print("[AETHER] [Fast Look] Fast look analysis failed.")
                    else:
                        add_analysis_entry(
                            gatherer_output=gatherer_out, 
                            annotator_output=annotator_out, 
                            starting_function=current_func_name,
                            structured_data=structured_commands
                        )
                except Exception as e:
                    print(f"[AETHER] [Fast Look] Error running fast look: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    FastLookHandler.is_running = False
            FastLookHandler.is_running = True
            start_pipeline(fast_look_thread(config, current_func_name, current_func_addr))
        except Exception as e:
            print(f"[AETHER] [Fast Look] Error running fast look: {e}")
            FastLookHandler.is_running = False
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

def strip_ai_annotations_from_current_function(current_func_addr: str, current_func_name: str) -> tuple[list, bool]:
    """
    Strip user comments and aire_ prefixed function names from the current function.
    Returns: (aire_functions_list, success)
    """
    # Strip user comments
    vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
    comments_stripped = False
    if vdui:
        cfunc = vdui.cfunc
        comment_locations = list(cfunc.user_cmts.keys())
        if comment_locations:
            for loc in comment_locations:
                cfunc.set_user_cmt(loc, "")
            cfunc.save_user_cmts()
            vdui.refresh_ctext()
            print("Removed all user comments from the current pseudocode function.")
            comments_stripped = True
        else:
            print("No user comments found in current function.")
    else:
        print("Warning: Could not access pseudocode view for comment stripping.")
    
    # Strip aire_ prefixed function names in the current function only
    aire_functions_container = {"functions": []}
    
    def strip_aire_functions():
        try:
            import idautils
            import idc
            
            # Get all callees of the current function
            func_addr_int = int(current_func_addr, 16)
            func_obj = idaapi.get_func(func_addr_int)
            if not func_obj:
                aire_functions_container["functions"] = []
                return
            
            aire_functions_to_restore = []
            
            # Iterate through all instructions in the current function
            for instruction_ea in idautils.FuncItems(func_obj.start_ea):
                # Get all references from this instruction
                for xref in idautils.XrefsFrom(instruction_ea, 0):
                    # Check if the reference destination is a function
                    callee_func = idaapi.get_func(xref.to)
                    if callee_func:
                        callee_name = idc.get_name(callee_func.start_ea, idaapi.GN_VISIBLE)
                        if callee_name and callee_name.startswith("aire_"):
                            callee_addr = hex(callee_func.start_ea)
                            # Avoid duplicates
                            if not any(f["address"] == callee_addr for f in aire_functions_to_restore):
                                aire_functions_to_restore.append({
                                    "name": callee_name,
                                    "address": callee_addr
                                })
            
            aire_functions_container["functions"] = aire_functions_to_restore
            
            if aire_functions_to_restore:
                print(f"Found {len(aire_functions_to_restore)} aire_ prefixed functions in current function to restore:")
                for func_info in aire_functions_to_restore:
                    print(f"  - {func_info['name']} at {func_info['address']}")
            else:
                print("No aire_ prefixed functions found in current function")
                
        except Exception as e:
            print(f"Error finding aire_ functions: {e}")
            aire_functions_container["functions"] = []
    
    # Execute the function search on main thread
    ida_kernwin.execute_sync(strip_aire_functions, ida_kernwin.MFF_READ)
    aire_functions = aire_functions_container["functions"]
    
    return aire_functions, comments_stripped or len(aire_functions) > 0

async def restore_aire_function_names(aire_functions: list, config: dict) -> bool:
    """Restore aire_ prefixed function names to IDA defaults using MCP."""
    if not aire_functions:
        return True
    
    # Test MCP connection first
    from ainalyse import test_mcp_connection
    mcp_success, mcp_msg = await test_mcp_connection(config["MCP_SERVER_URL"])
    if not mcp_success:
        print(f"[AETHER] MCP connection failed during function name restoration: {mcp_msg}")
        return False
    
    try:
        from mcp.client.session import ClientSession
        from mcp.client.sse import sse_client
        
        async with sse_client(config["MCP_SERVER_URL"]) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                
                success_count = 0
                for func_info in aire_functions:
                    try:
                        await session.call_tool("rename_function", {
                            "function_address": func_info["address"],
                            "new_name": ""  # Empty string restores IDA default name
                        })
                        print(f"[AETHER] Restored {func_info['address']} {func_info['name']} to IDA default name")
                        success_count += 1
                    except Exception as e:
                        print(f"[AETHER] Failed to restore {func_info['name']}: {e}")
                
                return success_count > 0
                        
    except Exception as e:
        print(f"[AETHER] Error during function name restoration: {e}")
        return False

class CustomPromptReAnnotateHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        config = load_config()
        
        # Use basic validation first
        is_valid, error_msg = validate_basic_config(config)
        if not is_valid:
            ida_kernwin.warning(error_msg)
            return 1
        
        # GET ALL IDA INFORMATION ON MAIN THREAD BEFORE STARTING BACKGROUND THREAD
        try:
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func:
                ida_kernwin.warning("No function found at current location.")
                return 1
            
            current_func_addr = hex(func.start_ea)
            current_func_name = ida_funcs.get_func_name(func.start_ea)
        except Exception as e:
            ida_kernwin.warning(f"Unable to get current function information: {e}")
            return 1
        
        # Strip AI annotations using shared function
        aire_functions, annotations_found = strip_ai_annotations_from_current_function(current_func_addr, current_func_name)
        
        if not annotations_found:
            print("[AETHER] [Custom Re-annotate] No AI annotations found to strip.")
        
        # Show custom prompt dialog
        dlg = CustomPromptDialog()
        if dlg.exec_():
            user_advice = dlg.get_user_advice()
            if not user_advice.strip():
                ida_kernwin.warning("Please provide some advice or feedback for re-annotation.")
                return 1
            
            print(f"[AETHER] [Custom Re-annotate] Starting custom re-annotation for function: {current_func_name}")

            @use_async_worker("CustomReannotate")
            async def custom_reannotate_thread(aire_functions, config, current_func_name, current_func_addr, user_advice):
                try:
                    # First restore aire_ function names if any were found
                    if aire_functions:
                        print(f"[AETHER] [Custom Re-annotate] Restoring {len(aire_functions)} aire_ prefixed function names...")
                        restoration_success = await restore_aire_function_names(aire_functions, config)
                        if not restoration_success:
                            print("[AETHER] [Custom Re-annotate] Warning: Some function name restorations may have failed.")
                    
                    # Now run the custom prompt analysis
                    success = await run_custom_prompt_analysis(config, current_func_name, current_func_addr, user_advice)
                    if not success:
                        print("[AETHER] [Custom Re-annotate] Custom re-annotation failed.")
                except Exception as e:
                    print(f"[AETHER] [Custom Re-annotate] Error running custom re-annotation: {e}")
                    import traceback
                    traceback.print_exc()

            start_pipeline(custom_reannotate_thread(aire_functions, config, current_func_name, current_func_addr, user_advice))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

class StripAIAnnotationsHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        config = load_config()
        
        # Use basic validation first
        is_valid, error_msg = validate_basic_config(config)
        if not is_valid:
            ida_kernwin.warning(error_msg)
            return 1
        
        # GET ALL IDA INFORMATION ON MAIN THREAD BEFORE STARTING BACKGROUND THREAD
        try:
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func:
                ida_kernwin.warning("No function found at current location.")
                return 1
            
            current_func_addr = hex(func.start_ea)
            current_func_name = ida_funcs.get_func_name(func.start_ea)
        except Exception as e:
            ida_kernwin.warning(f"Unable to get current function information: {e}")
            return 1
        
        # Strip AI annotations using shared function
        aire_functions, annotations_found = strip_ai_annotations_from_current_function(current_func_addr, current_func_name)
        
        if not annotations_found:
            print(f"[AETHER] [Strip Only] No AI annotations found in function '{current_func_name}' to strip.")
            ida_kernwin.info(f"No AI annotations (comments or aire_ function names) found in function '{current_func_name}'.")
            return 1
        
        print(f"[AETHER] [Strip Only] Stripped AI annotations from function: {current_func_name}")

        @use_async_worker("StripAnnotate")
        async def strip_thread(aire_functions, config, current_func_name):
            try:
                # Restore aire_ function names if any were found
                if aire_functions:
                    print(f"[AETHER] [Strip Only] Restoring {len(aire_functions)} aire_ prefixed function names...")
                    restoration_success = await restore_aire_function_names(aire_functions, config)
                    if restoration_success:
                        print(f"[AETHER] [Strip Only] Successfully stripped AI annotations from function '{current_func_name}'.")
                    else:
                        print("[AETHER] [Strip Only] Warning: Some function name restorations may have failed.")
                else:
                    print(f"[AETHER] [Strip Only] Successfully stripped comments from function '{current_func_name}'.")
                    
            except Exception as e:
                print(f"[AETHER] [Strip Only] Error during annotation stripping: {e}")
                import traceback
                traceback.print_exc()

        start_pipeline(strip_thread(aire_functions, config, current_func_name))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET
